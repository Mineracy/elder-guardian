import { Hono } from 'hono'
import { createSession, hashPassword, requireAuth, verifyPassword } from '../auth'
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
  return c.json({ token, user: { id, email, role } }, 201)
})

auth.post('/signin', async (c) => {
  const body = await c.req.json().catch(() => ({}))
  const email = String(body.email ?? '').trim().toLowerCase()
  const password = String(body.password ?? '')

  const user = await c.env.DB.prepare(
    'SELECT id, email, role, password_hash FROM users WHERE email = ?',
  )
    .bind(email)
    .first<{ id: string; email: string; role: string; password_hash: string }>()

  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return c.json({ error: 'Incorrect email or password' }, 401)
  }

  const token = await createSession(c.env.DB, user.id)
  return c.json({ token, user: { id: user.id, email: user.email, role: user.role } })
})

auth.get('/me', requireAuth, (c) => c.json({ user: c.get('user') }))

export default auth
