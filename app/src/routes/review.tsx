import { Hono } from 'hono'
import type { FC, PropsWithChildren } from 'hono/jsx'
import { resolveIntervention } from '../resolve'
import type { AppEnv } from '../types'

type Review = {
  id: string
  user_id: string
  protected_email: string
  target_url: string
  domain: string
  threat_level: string
  risk_summary: string
  trusted_contact_alert: string
  status: string
  expires_at: number
  review_token: string
}

const css = `
body{margin:0;font-family:system-ui,sans-serif;background:#f3f4f6;color:#111827}
main{max-width:560px;margin:32px auto;padding:24px;background:#fff;border-radius:16px;box-shadow:0 2px 12px #0001}
h1{font-size:22px;margin:0 0 12px}
.badge{display:inline-block;padding:2px 10px;border-radius:999px;font-weight:700;font-size:13px;background:#fde68a}
.badge.HIGH,.badge.CRITICAL{background:#fecaca}.badge.LOW{background:#bbf7d0}
code{display:block;word-break:break-all;background:#f3f4f6;padding:8px;border-radius:8px;margin:8px 0}
.actions{display:flex;gap:12px;margin-top:20px}
button{flex:1;font-size:18px;font-weight:700;padding:16px;border:0;border-radius:12px;color:#fff;cursor:pointer}
.allow{background:#15803d}.deny{background:#b91c1c}
label{display:block;margin-top:16px;font-size:14px}
`

const Layout: FC<PropsWithChildren<{ title: string }>> = ({ title, children }) => (
  <html lang="en">
    <head>
      <meta charset="UTF-8" />
      <meta name="viewport" content="width=device-width, initial-scale=1" />
      <meta name="robots" content="noindex" />
      <title>{title}</title>
      <style>{css}</style>
    </head>
    <body>
      <main>{children}</main>
    </body>
  </html>
)

const Done: FC<{ status: string }> = ({ status }) => (
  <Layout title="Guardian review">
    <h1>{status === 'allowed' ? 'You allowed this' : 'You denied this'}</h1>
    <p>
      {status === 'allowed'
        ? 'They can now continue to the page.'
        : 'The page stays blocked, and they will see a short explanation of the warning signs. Thank you for looking out for them.'}
    </p>
  </Layout>
)

const review = new Hono<AppEnv>()

async function load(db: D1Database, token: string) {
  return db
    .prepare(
      `SELECT r.id, r.user_id, u.email AS protected_email, r.target_url, r.domain, r.threat_level,
              r.risk_summary, r.trusted_contact_alert, r.status, r.expires_at, r.review_token
       FROM intervention_requests r JOIN users u ON u.id = r.user_id
       WHERE r.review_token = ?`,
    )
    .bind(token)
    .first<Review>()
}

review.get('/:token', async (c) => {
  const r = await load(c.env.DB, c.req.param('token'))
  if (!r) return c.html(<Layout title="Not found"><h1>This link isn't valid</h1></Layout>, 404)
  if (r.status !== 'pending') return c.html(<Done status={r.status} />)
  if (r.expires_at < Date.now()) {
    return c.html(<Layout title="Expired"><h1>This request has expired</h1><p>It was denied automatically.</p></Layout>)
  }

  return c.html(
    <Layout title="Guardian review">
      <h1>We think {r.protected_email} is at risk</h1>
      <p><span class={`badge ${r.threat_level}`}>{r.threat_level} risk</span></p>
      <p>{r.risk_summary}</p>
      <p>They tried to open:</p>
      <code>{r.target_url}</code>
      <form method="post">
        <label>
          <input type="checkbox" name="always_allow" value="1" /> If allowing, always trust{' '}
          <strong>{r.domain}</strong> for them
        </label>
        <div class="actions">
          <button class="allow" name="decision" value="allow">Allow</button>
          <button class="deny" name="decision" value="deny">Deny</button>
        </div>
      </form>
    </Layout>,
  )
})

review.post('/:token', async (c) => {
  const db = c.env.DB
  const r = await load(db, c.req.param('token'))
  if (!r) return c.html(<Layout title="Not found"><h1>This link isn't valid</h1></Layout>, 404)
  if (r.status !== 'pending') return c.html(<Done status={r.status} />)

  const form = await c.req.parseBody()
  const decision = form.decision === 'allow' ? 'allowed' : form.decision === 'deny' ? 'denied' : null
  if (!decision) return c.text('Bad request', 400)

  const final = await resolveIntervention(db, r, decision, form.always_allow === '1')
  return c.html(<Done status={final} />)
})

export default review
