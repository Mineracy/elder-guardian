# Elder Guardian

Protects vulnerable people from scams. A Chrome extension holds risky browsing events, a Hono/Cloudflare Workers
backend asks a **trusted contact** to approve or deny them by email, and Gemini explains the threat in plain,
non-judgmental language.

```
extension (listens) ──intercept──▶ backend (Hono + D1) ──email──▶ trusted contact [Allow] [Deny]
      ▲                                  │ Gemini: risk analysis + education + contact alert
      └──── allow: release hold / deny: show educational message ◀──┘
```

## Flow
1. Protected user signs up in the extension popup and connects a trusted contact's email.
2. Navigating to a domain not on their whitelist (or a page with fake tech-support text, or a remote-access-tool
   download) puts the tab on an **"Awaiting verification"** page and creates an intervention request.
3. The backend asks Gemini for `threat_level`, `risk_summary`, `user_education_message`, `trusted_contact_alert`
   (structured JSON, temperature 0.2; falls back to a hardcoded Medium Risk response if Gemini fails) and emails the
   trusted contact a secure review link.
4. The contact opens the link and presses **Allow** (optionally "always trust this site") or **Deny**.
5. The extension polls: Allow releases the hold; Deny shows the educational message. Unanswered requests expire
   after 24h and count as denied.

## Run locally
One process serves everything: Vite runs the React site and the Hono Worker (with a local D1) on the same origin.
```sh
cd app
npm install
npm run db:migrate:local
npm run dev            # site + API on http://localhost:3000
```
Load `extension/` via `chrome://extensions` → Developer mode → Load unpacked.

The site (`app/client`) has a landing page and a login-gated **Elder Guardian dashboard**: per protected person, a log of
suspicious activity with Allow / Deny (+ "add to whitelist"), a view of their whitelist, and "remove self as trusted
Elder Guardian". Elder Guardians sign up on the site with the email the protected person entered, then confirm it via an emailed
link (printed to the dev console without `RESEND_API_KEY`; the API also echoes `devVerifyUrl` in dev).

Configuration lives in one git-ignored env file. Copy the template and fill in your keys:
```sh
cp app/.dev.vars.example app/.dev.vars
```
It holds `GEMINI_API_KEY`, `RESEND_API_KEY`, `EMAIL_FROM`, `GEMINI_MODEL`, `APP_BASE_URL` and `ENVIRONMENT`; see the
comments in `.dev.vars.example`. Everything is optional locally: without a Gemini key the Medium Risk fallback is
used, without a Resend key emails are printed to the console. `ENVIRONMENT=dev` (set in the example) also echoes
review/verification links in API responses. **Never set it in production**, otherwise the protected person could
approve their own requests. Without the file nothing is echoed.

## Deploy
```sh
cd app
npx wrangler d1 create guardian        # put the id in wrangler.jsonc
npm run db:migrate:remote
npx wrangler secret put GEMINI_API_KEY
npx wrangler secret put RESEND_API_KEY
# plain settings (EMAIL_FROM, APP_BASE_URL, GEMINI_MODEL): Cloudflare dashboard > Worker > Settings > Variables
npm run deploy                         # builds the site and deploys the single Worker
```
Set `APP_BASE_URL` to the Worker URL (leave `ENVIRONMENT` unset), and update `extension/src/config.js` and
`host_permissions` in `extension/manifest.json`.

## Design decisions
- Passwords use salted PBKDF2-SHA256 (Web Crypto) rather than a bare SHA-256; session tokens are stored hashed.
- Only the trusted contact can grow the whitelist ("always allow"), and the contact can only be set once, so a
  scammer coaching the victim can't simply whitelist their own site or swap in their own "trusted contact".
- Elder Guardian accounts must verify their email before the dashboard API works, so nobody can approve scams just by
  signing up with an Elder Guardian's address.
- All AI output is rendered as text (never HTML) and page content sent to Gemini is fenced as untrusted data.

## Known gaps
- No rate limiting; sign-out in the popup isn't gated; large-payment / unsafe-email detection from the design notes
  is not implemented yet (detection currently covers non-whitelisted domains, fake tech-support text, and
  remote-access downloads); there is no flow for changing the trusted contact (after an Elder Guardian removes themselves, the protected person
  can set a new one).
