import type { Bindings } from './types'

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`)

export async function sendReviewEmail(
  env: Bindings,
  opts: {
    to: string
    protectedEmail: string
    alertText: string
    reviewUrl: string
    targetUrl: string
    threatLevel: string
  },
) {
  const subject = `Action needed: ${opts.protectedEmail} may be at risk`
  const text = `Hi,\n\nWe think ${opts.protectedEmail} is at risk.\n\n${opts.alertText}\n\nLink they tried to open: ${opts.targetUrl}\nThreat level: ${opts.threatLevel}\n\nPlease review it and choose Allow or Deny:\n${opts.reviewUrl}\n\nThey are waiting on your answer.`
  const html = `<p>Hi,</p>
<p>We think <strong>${escapeHtml(opts.protectedEmail)}</strong> is at risk.</p>
<p>${escapeHtml(opts.alertText)}</p>
<p>Link they tried to open: <code>${escapeHtml(opts.targetUrl)}</code><br>Threat level: <strong>${escapeHtml(opts.threatLevel)}</strong></p>
<p><a href="${escapeHtml(opts.reviewUrl)}" style="display:inline-block;padding:12px 20px;background:#1d4ed8;color:#fff;border-radius:8px;text-decoration:none">Review and decide</a></p>
<p>They are waiting on your answer.</p>`

  if (!env.RESEND_API_KEY) {
    console.log(`[email:dev] to=${opts.to}\n${subject}\n${text}`)
    return
  }

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${env.RESEND_API_KEY}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      from: env.EMAIL_FROM ?? 'Guardian <onboarding@resend.dev>',
      to: [opts.to],
      subject,
      text,
      html,
    }),
  })
  if (!res.ok) {
    throw new Error(`Email provider responded ${res.status}: ${await res.text()}`)
  }
}
