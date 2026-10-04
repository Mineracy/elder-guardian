import { Hono } from 'hono'
import { randomToken, requireAuth } from '../auth'
import { sendReviewEmail } from '../email'
import { normalizeDomain } from '../domains'
import { analyzeThreat } from '../gemini'
import { analyzeUrl, maxLevel, TRIGGER_FLOORS } from '../signals'
import type { AppEnv } from '../types'

const REVIEW_WINDOW_MS = 24 * 60 * 60 * 1000
const DEDUPE_WINDOW_MS = 10 * 60 * 1000

const interventions = new Hono<AppEnv>()
interventions.use('*', requireAuth)

type Row = {
  id: string
  target_url: string
  threat_level: string
  user_education_message: string
  status: string
  expires_at: number
}

const publicView = (r: Row) => ({
  id: r.id,
  status: r.status,
  targetUrl: r.target_url,
  threatLevel: r.threat_level,
  userEducationMessage: r.user_education_message,
})

/** Expired reviews count as denied: a missing answer must never release the hold. */
async function expireIfNeeded(db: D1Database, r: Row): Promise<Row> {
  if (r.status === 'pending' && r.expires_at < Date.now()) {
    await db
      .prepare("UPDATE intervention_requests SET status = 'denied', resolved_at = ? WHERE id = ? AND status = 'pending'")
      .bind(Date.now(), r.id)
      .run()
    return { ...r, status: 'denied' }
  }
  return r
}

interventions.post('/', async (c) => {
  const user = c.get('user')
  if (user.role !== 'protected') return c.json({ error: 'Only protected accounts can request approval' }, 403)

  const body = await c.req.json().catch(() => ({}))
  const targetUrl = String(body.targetUrl ?? '').slice(0, 2048)
  const triggerType = String(body.triggerType ?? 'NON_WHITELISTED_DOMAIN').slice(0, 64)
  const context = body.context ? String(body.context).slice(0, 1000) : undefined

  let domain: string | null = null
  try {
    const u = new URL(targetUrl)
    if (u.protocol === 'http:' || u.protocol === 'https:') domain = normalizeDomain(u.hostname)
  } catch {
    /* handled below */
  }
  if (!domain) return c.json({ error: 'targetUrl must be a valid http(s) URL' }, 400)

  const db = c.env.DB

  // Reloading the hold page must not spam the trusted contact.
  const recent = await db
    .prepare(
      `SELECT id, target_url, threat_level, user_education_message, status, expires_at
       FROM intervention_requests
       WHERE user_id = ? AND target_url = ? AND created_at > ?
       ORDER BY created_at DESC LIMIT 1`,
    )
    .bind(user.id, targetUrl, Date.now() - DEDUPE_WINDOW_MS)
    .first<Row>()
  if (recent && recent.status !== 'allowed') {
    return c.json(publicView(await expireIfNeeded(db, recent)))
  }

  const { results: contacts } = await db
    .prepare('SELECT trusted_email FROM contact_pairings WHERE protected_user_id = ?')
    .bind(user.id)
    .all<{ trusted_email: string }>()

  const { signals, floor: urlFloor } = analyzeUrl(targetUrl)
  const signalLabels = signals.map((s) => s.label)
  const { analysis: aiAnalysis, usedFallback, aiError } = await analyzeThreat(c.env, {
    targetUrl,
    domain,
    triggerType,
    context,
    protectedEmail: user.email,
    signals: signalLabels,
  })

  // Our own checks set a minimum severity so a lenient (or unavailable) AI can't under-rate a clear scam.
  let threatLevel = aiAnalysis.threat_level
  for (const floor of [urlFloor, Object.hasOwn(TRIGGER_FLOORS, triggerType) ? TRIGGER_FLOORS[triggerType] : null]) {
    if (floor) threatLevel = maxLevel(threatLevel, floor)
  }
  const analysis = { ...aiAnalysis, threat_level: threatLevel }

  const id = crypto.randomUUID()
  const reviewToken = randomToken()
  const now = Date.now()
  // With nobody to approve, fail closed instead of leaving the person waiting forever.
  const status = contacts.length === 0 ? 'denied' : 'pending'

  await db
    .prepare(
      `INSERT INTO intervention_requests
       (id, user_id, target_url, domain, trigger_type, context, threat_level, risk_summary,
        user_education_message, trusted_contact_alert, review_token, status, used_fallback,
        created_at, expires_at, resolved_at, signals, ai_error)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      id, user.id, targetUrl, domain, triggerType, context ?? null, analysis.threat_level,
      analysis.risk_summary, analysis.user_education_message, analysis.trusted_contact_alert,
      reviewToken, status, usedFallback ? 1 : 0, now, now + REVIEW_WINDOW_MS,
      status === 'denied' ? now : null, JSON.stringify(signals), aiError ?? null,
    )
    .run()

  const baseUrl = c.env.APP_BASE_URL ?? new URL(c.req.url).origin
  const reviewUrl = `${baseUrl}/review/${reviewToken}`
  const emailResults = await Promise.allSettled(
    contacts.map((ct) =>
      sendReviewEmail(c.env, {
        to: ct.trusted_email,
        protectedEmail: user.email,
        alertText: analysis.trusted_contact_alert,
        reviewUrl,
        targetUrl,
        threatLevel: analysis.threat_level,
      }),
    ),
  )
  emailResults.forEach((r) => r.status === 'rejected' && console.error('[email] failed:', r.reason))

  const view = {
    id,
    status,
    targetUrl,
    threatLevel: analysis.threat_level,
    userEducationMessage: analysis.user_education_message,
    ...(status === 'denied' ? { reason: 'no_trusted_contact' } : {}),
  }
  // Echoing the link would let the protected person approve themselves, so dev only.
  return c.json(c.env.ENVIRONMENT === 'dev' ? { ...view, devReviewUrl: reviewUrl } : view, 201)
})

interventions.get('/:id', async (c) => {
  const row = await c.env.DB.prepare(
    `SELECT id, target_url, threat_level, user_education_message, status, expires_at
     FROM intervention_requests WHERE id = ? AND user_id = ?`,
  )
    .bind(c.req.param('id'), c.get('user').id)
    .first<Row>()
  if (!row) return c.json({ error: 'Not found' }, 404)
  return c.json(publicView(await expireIfNeeded(c.env.DB, row)))
})

export default interventions
