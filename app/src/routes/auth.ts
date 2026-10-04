import { Hono } from 'hono'
import { createSession, hashPassword, requireAuth, sendVerification, sha256Hex, verifyPassword } from '../auth'
import { DEFAULT_WHITELIST } from '../domains'
import type { AppEnv } from '../types'

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

const auth = new Hono<AppEnv>()

auth.post('/signup', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const email = String(body.email ?? '').trim().toLowerCase()
  const password = String(body.password ?? '')
  const role = body.role === 'trusted' ? 'trusted' : 'protected'

  if (!EMAIL_RE.test(email)) return c.json({ error: 'Enter a valid email address' }, 400)
  if (password.length < 8) return c.json({ error: 'Password must be at least 8 characters' }, 400)

  const db = c.env.DB
  const existing = await db.prepare('SELECT id FROM users WHERE email = ?').bind(email).first()
  if (existing) return c.json({ error: 'An account with that email already exists' }, 409)

  const id = crypto.randomUUID()
  const now = Date.now()
  const statements = [
    db
      .prepare('INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)')
      .bind(id, email, await hashPassword(password), role, now),
  ]
  if (role === 'protected') {
    for (const domain of DEFAULT_WHITELIST) {
      statements.push(
        db
          .prepare(
            'INSERT INTO whitelist_domains (id, user_id, domain, created_at) VALUES (?, ?, ?, ?)',
          )
          .bind(crypto.randomUUID(), id, domain, now),
      )
    }
  }
  await db.batch(statements)

  const token = await createSession(db, id)
  const user = { id, email, role, email_verified: 0 }
  if (role === 'trusted') {
    const verifyUrl = await sendVerification(c.env, c.req.url, user)
    return c.json({ token, user, ...(c.env.ENVIRONMENT === 'dev' ? { devVerifyUrl: verifyUrl } : {}) }, 201)
  }
  return c.json({ token, user }, 201)
})

auth.post('/signin', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const email = String(body.email ?? '').trim().toLowerCase()
  const password = String(body.password ?? '')

  const user = await c.env.DB.prepare(
    'SELECT id, email, role, email_verified, password_hash FROM users WHERE email = ?',
  )
    .bind(email)
    .first<{ id: string; email: string; role: string; email_verified: number; password_hash: string }>()

  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return c.json({ error: 'Incorrect email or password' }, 401)
  }

  const token = await createSession(c.env.DB, user.id)
  return c.json({ token, user: { id: user.id, email: user.email, role: user.role, email_verified: user.email_verified } })
})

auth.post('/resend-verification', requireAuth, async (c) => {
  const user = c.get('user')
  if (user.email_verified) return c.json({ ok: true })
  const url = await sendVerification(c.env, c.req.url, user)
  return c.json({ ok: true, ...(c.env.ENVIRONMENT === 'dev' ? { devVerifyUrl: url } : {}) })
})

auth.get('/me', requireAuth, (c) => c.json({ user: c.get('user') }))

/** Mounted at /verify: the link in the confirmation email lands here. */
export const verify = new Hono<AppEnv>()

verify.get('/:token', async (c) => {
  const db = c.env.DB
  const hash = await sha256Hex(c.req.param('token'))
  const row = await db
    .prepare('SELECT user_id FROM email_verifications WHERE token_hash = ? AND expires_at > ?')
    .bind(hash, Date.now())
    .first<{ user_id: string }>()
  if (!row) return c.html('<h1>This confirmation link is invalid or has expired.</h1>', 400)

  await db.batch([
    db.prepare('UPDATE users SET email_verified = 1 WHERE id = ?').bind(row.user_id),
    db.prepare('DELETE FROM email_verifications WHERE user_id = ?').bind(row.user_id),
  ])
  return c.redirect('/dashboard?verified=1')
})

export default auth
