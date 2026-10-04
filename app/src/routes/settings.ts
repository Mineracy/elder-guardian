import { Hono } from 'hono'
import { requireAuth } from '../auth'
import type { AppEnv } from '../types'

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/

const settings = new Hono<AppEnv>()
settings.use('*', requireAuth)

// --- Trusted contact pairing -------------------------------------------------

settings.get('/contacts', async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT id, trusted_email FROM contact_pairings WHERE protected_user_id = ? ORDER BY created_at',
  )
    .bind(c.get('user').id)
    .all()
  return c.json({ contacts: results })
})

settings.post('/contacts', async (c) => {
  const user = c.get('user')
  if (user.role !== 'protected') return c.json({ error: 'Only protected accounts have contacts' }, 403)

  const body = await c.req.json().catch(() => ({}))
  const email = String(body.email ?? '').trim().toLowerCase()
  if (!EMAIL_RE.test(email)) return c.json({ error: 'Enter a valid email address' }, 400)
  if (email === user.email) return c.json({ error: 'Your trusted contact must be someone else' }, 400)

  // A scammer coaching the victim must not be able to swap in their own "trusted contact".
  const existing = await c.env.DB.prepare(
    'SELECT 1 FROM contact_pairings WHERE protected_user_id = ?',
  )
    .bind(user.id)
    .first()
  if (existing) return c.json({ error: 'A trusted contact is already set' }, 409)

  await c.env.DB.prepare(
    'INSERT INTO contact_pairings (id, protected_user_id, trusted_email, created_at) VALUES (?, ?, ?, ?)',
  )
    .bind(crypto.randomUUID(), user.id, email, Date.now())
    .run()
  return c.json({ ok: true }, 201)
})

// --- Whitelist ---------------------------------------------------------------

settings.get('/whitelist', async (c) => {
  const { results } = await c.env.DB.prepare(
    'SELECT id, domain FROM whitelist_domains WHERE user_id = ? ORDER BY domain',
  )
    .bind(c.get('user').id)
    .all()
  return c.json({ domains: results })
})

// The whitelist is read-only here: only the trusted contact grows it ("Always allow" on review).

export default settings
