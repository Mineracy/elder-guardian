import type { Bindings } from './types'

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (ch) => `&#${ch.charCodeAt(0)};`)

async function sendEmail(
  env: Bindings,
  msg: { to: string; subject: string; text: string; html: string },
) {
  if (!env.RESEND_API_KEY) {
    console.log(`[email:dev] to=${msg.to}\n${msg.subject}\n${msg.text}`)
    return
  }
  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${env.RESEND_API_KEY}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      from: env.EMAIL_FROM ?? 'Elder Guardian <hello@elderguardian.vip>',
      to: [msg.to],
      subject: msg.subject,
      text: msg.text,
      html: msg.html,
    }),
  })
  if (!res.ok) throw new Error(`Email provider responded ${res.status}: ${await res.text()}`)
}

export function sendVerificationEmail(env: Bindings, to: string, verifyUrl: string) {
  return sendEmail(env, {
    to,
    subject: 'Confirm your email to become a trusted Elder Guardian',
    text: `Confirm your email address so you can review requests for the people you protect:\n${verifyUrl}\n\nIf you didn't create this account, ignore this email.`,
    html: `<p>Confirm your email address so you can review requests for the people you protect.</p><p><a href="${escapeHtml(verifyUrl)}">Confirm my email</a></p><p>If you didn't create this account, ignore this email.</p>`,
  })
}

export async function sendReviewEmail(
  env: Bindings,
  opts: {
    to: string
    protectedEmail: string
    alertText: string
    reviewUrl: string
    targetUrl: string
    threatLevel: string
    amountCents?: number
  },
) {
  const amount = opts.amountCents ? `$${(opts.amountCents / 100).toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}` : null
  const subject = `Action needed: ${opts.protectedEmail} may be at risk`
  const text = `Hi,\n\nWe think ${opts.protectedEmail} is at risk.\n\n${opts.alertText}\n\n${amount ? `Transaction amount: ${amount}\n` : ''}Link they tried to open: ${opts.targetUrl}\nThreat level: ${opts.threatLevel}\n\nPlease review it and choose Allow or Deny:\n${opts.reviewUrl}\n\nThey are waiting on your answer.`
  const html = `<p>Hi,</p>
<p>We think <strong>${escapeHtml(opts.protectedEmail)}</strong> is at risk.</p>
<p>${escapeHtml(opts.alertText)}</p>
${amount ? `<p>Transaction amount: <strong>${escapeHtml(amount)}</strong></p>` : ''}
<p>Link they tried to open: <code>${escapeHtml(opts.targetUrl)}</code><br>Threat level: <strong>${escapeHtml(opts.threatLevel)}</strong></p>
<p><a href="${escapeHtml(opts.reviewUrl)}" style="display:inline-block;padding:12px 20px;background:#1d4ed8;color:#fff;border-radius:8px;text-decoration:none">Review and decide</a></p>
<p>They are waiting on your answer.</p>`

  await sendEmail(env, { to: opts.to, subject, text, html })
}
