import { Hono } from 'hono'
import { requireAuth } from '../auth'
import { resolveIntervention } from '../resolve'
import type { AppEnv } from '../types'

const ACTIVITY_LIMIT = 50

const guardian = new Hono<AppEnv>()
guardian.use('*', requireAuth)
guardian.use('*', async (c, next) => {
  const user = c.get('user')
  if (user.role !== 'trusted') return c.json({ error: 'Guardian accounts only' }, 403)
  // Without this, anyone could sign up with a guardian's address and approve scams.
  if (!user.email_verified) return c.json({ error: 'verify_email' }, 403)
  await next()
})

/** True when `protectedId` has paired this guardian's email. */
async function isPaired(db: D1Database, protectedId: string, guardianEmail: string) {
  return !!(await db
    .prepare('SELECT 1 FROM contact_pairings WHERE protected_user_id = ? AND trusted_email = ?')
    .bind(protectedId, guardianEmail)
    .first())
}

guardian.get('/dashboard', async (c) => {
  const db = c.env.DB
  const now = Date.now()
  const { results: people } = await db
    .prepare(
      `SELECT u.id, u.email FROM contact_pairings p JOIN users u ON u.id = p.protected_user_id
       WHERE p.trusted_email = ? ORDER BY u.email`,
    )
    .bind(c.get('user').email)
    .all<{ id: string; email: string }>()

  const protectees = await Promise.all(
    people.map(async (p) => {
      const [activity, whitelist] = await Promise.all([
        db
          .prepare(
            `SELECT id, target_url, domain, trigger_type, threat_level, risk_summary, status, created_at, expires_at
             FROM intervention_requests WHERE user_id = ? ORDER BY created_at DESC LIMIT ?`,
          )
          .bind(p.id, ACTIVITY_LIMIT)
          .all<{ status: string; expires_at: number }>(),
        db
          .prepare('SELECT domain FROM whitelist_domains WHERE user_id = ? ORDER BY domain')
          .bind(p.id)
          .all<{ domain: string }>(),
      ])
      // Expired requests are effectively denied (see interventions.ts), so don't offer Allow on them.
      const items = activity.results.map((a) =>
        a.status === 'pending' && a.expires_at < now ? { ...a, status: 'denied' } : a,
      )
      return {
        id: p.id,
        email: p.email,
        pendingCount: items.filter((a) => a.status === 'pending').length,
        activity: items,
        whitelist: whitelist.results.map((w) => w.domain),
      }
    }),
  )
  return c.json({ protectees })
})

guardian.post('/interventions/:id/decision', async (c) => {
  const db = c.env.DB
  const body = await c.req.json().catch(() => ({}))
  if (body.decision !== 'allow' && body.decision !== 'deny') {
    return c.json({ error: 'decision must be "allow" or "deny"' }, 400)
  }
  const req = await db
    .prepare('SELECT id, user_id, domain, expires_at FROM intervention_requests WHERE id = ?')
    .bind(c.req.param('id'))
    .first<{ id: string; user_id: string; domain: string; expires_at: number }>()
  if (!req || !(await isPaired(db, req.user_id, c.get('user').email))) {
    return c.json({ error: 'Not found' }, 404)
  }
  const status = await resolveIntervention(
    db,
    req,
    body.decision === 'allow' ? 'allowed' : 'denied',
    body.addToWhitelist === true,
  )
  return c.json({ status })
})

/** "Remove self as trusted guardian". */
guardian.delete('/protectees/:id', async (c) => {
  const db = c.env.DB
  await db
    .prepare('DELETE FROM contact_pairings WHERE protected_user_id = ? AND trusted_email = ?')
    .bind(c.req.param('id'), c.get('user').email)
    .run()
  return c.json({ ok: true })
})

export default guardian
