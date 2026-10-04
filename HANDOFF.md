# Anti-Scam Guardian: Developer Handoff

Branch: `claude/anti-scam-guardian-agent-eavbcf` · PR: https://github.com/Mineracy/rowdyhack/pull/1

## What it is
Protects vulnerable people (e.g. older adults) from scams. A Chrome extension **holds** risky browsing events, a
Hono backend on Cloudflare Workers asks a **trusted contact (guardian)** to Allow/Deny, and Gemini writes the risk
analysis, an empathetic message for the protected user, and an alert for the guardian. A React site lets guardians
review and decide from a dashboard.

```
extension ──hold + create request──▶ Hono Worker (D1) ──email link──▶ guardian (review page or dashboard)
    ▲                                    │ Gemini: threat_level, risk_summary,
    └── poll: allow → release,           │ user_education_message, trusted_contact_alert
        deny → show education ◀──────────┘
```

## Repo layout
```
app/                      single deployable: Hono API + React site (one process)
  src/index.ts            Hono app, CORS, route mounting
  src/auth.ts             PBKDF2 hashing, hashed session tokens, requireAuth, email-verification helper
  src/gemini.ts           Gemini call (responseSchema, temp 0.2, 10s timeout) + hardcoded Medium Risk fallback
  src/email.ts            Resend sender (console.log in dev without a key)
  src/resolve.ts          shared Allow/Deny logic (first answer wins, expired => denied, optional whitelist add)
  src/domains.ts          domain normalising + default whitelist seeded at signup
  src/routes/auth.ts      /api/auth/{signup,signin,me,resend-verification}, /verify/:token
  src/routes/settings.ts  /api/contacts (get, post), /api/whitelist (get)
  src/routes/interventions.ts  POST/GET /api/interventions (extension side)
  src/routes/guardian.ts  /api/guardian/{dashboard, interventions/:id/decision, protectees/:id DELETE}
  src/routes/review.tsx   server-rendered emailed review page (/review/:token)
  migrations/             0001_init.sql, 0002_email_verification.sql
  client/                 React (Vite, react-router): Landing, Login, Dashboard, ProtecteeCard
  client/tsconfig.json    MUST stay separate (see Gotchas)
  vite.config.ts          react() + @cloudflare/vite-plugin => one process
  wrangler.jsonc          D1 binding, assets (SPA fallback), vars
extension/                Manifest V3 extension
  src/background.js       webNavigation hold, download interception, message router
  src/hold.{html,js,css}  "Awaiting verification" page, polls, shows allow/deny/education
  src/popup.{html,js,css} sign in/up, connect trusted contact, view whitelist
  src/content.js          fake tech-support phrase detection
  src/api.js, config.js   fetch helpers, session/whitelist/pass storage, API_BASE
```

## Data model (D1)
`users` (role: protected|trusted, email_verified) · `sessions` (token hash) · `contact_pairings`
(protected_user_id -> trusted_email) · `whitelist_domains` · `intervention_requests`
(target_url, domain, trigger_type, threat_level, risk_summary, user_education_message, trusted_contact_alert,
review_token, status pending|allowed|denied, used_fallback, expires_at 24h) · `email_verifications`.

## Key flows
1. Protected user signs up in the extension popup (gets a default whitelist) and connects one trusted email.
2. Navigation to a non-whitelisted domain, fake tech-support page text, or AnyDesk/TeamViewer-style download is held.
3. Hold page calls `POST /api/interventions`: Gemini analysis, row saved, guardian emailed a review link. Repeats within
   10 min for the same URL are deduplicated. No contact set => denied immediately (fail closed).
4. Guardian decides via the emailed link or the dashboard (optionally "add to whitelist"). Hold page polls every 3s:
   allow => 30-min pass + redirect; deny => education message. Unanswered after 24h => denied.
5. Guardians use the website: sign up (role trusted) with the email the protected person entered, **verify email**,
   then the dashboard shows per-person activity, Allow/Deny, whitelist viewer, "remove self as guardian".

## Run locally
```sh
cd app && npm install
npm run db:migrate:local
npm run dev            # site + API on http://localhost:3000 (one process)
```
Load `extension/` unpacked at `chrome://extensions` (Developer mode). Secrets/settings: `cp app/.dev.vars.example
app/.dev.vars` and fill it in (git-ignored; all optional locally). With `ENVIRONMENT=dev` the API echoes
`devReviewUrl` / `devVerifyUrl` and emails print to the console.

## Deploy
`npx wrangler d1 create guardian` (put the id in `wrangler.jsonc`), `npm run db:migrate:remote`,
`wrangler secret put GEMINI_API_KEY` / `RESEND_API_KEY`, set `APP_BASE_URL`, **leave `ENVIRONMENT` unset**
(`dev` would let the protected user approve themselves via the echoed link), update `extension/src/config.js` and
`host_permissions` in `extension/manifest.json`, then `npm run deploy`.

## Design decisions worth keeping
- PBKDF2-SHA256 + salt (not bare SHA-256); session tokens stored hashed.
- Protected users **cannot edit their whitelist**; only a guardian's "always allow" grows it. The trusted contact is
  settable **once** (prevents a scammer coaching the victim into whitelisting or swapping the guardian).
- Guardian accounts must verify email before the guardian API works (email ownership is otherwise unproven).
- AI output is rendered as text only; page content sent to Gemini is fenced as untrusted data.
- Expired pending requests count as denied; first decision wins.

## Verified vs not
Verified: backend flow via curl; full extension flow in real Chromium (hold, allow + always-allow, deny, fake
tech-support detection, popup); full guardian website flow in dev and the production build (signup, verification
gate, Allow/Deny, whitelist, remove self, mobile layout); fresh clone starts cleanly; TypeScript typechecks.
**Not verified:** live Gemini call (no key; only the fallback ran), real email delivery, a real deployment.

## Known gaps / next steps
- Large-payment and unsafe-email detection from the original notes are not built (detection = non-whitelisted
  domain, fake tech-support text, remote-access downloads).
- No rate limiting; popup sign-out is not gated; no flow to change the trusted contact (possible after a guardian
  removes themself); multiple guardians per person is supported by the schema but the UI sets just one.
- Tune the Gemini model/prompt with a real key (`GEMINI_MODEL`, default `gemini-2.5-flash`).
- Whitelist is exact-domain plus subdomains; no allowlist import or guardian-side removal of entries yet.

## Gotchas
- `client/tsconfig.json` must exist: the Worker's `tsconfig.json` sets `jsxImportSource: hono/jsx`, which otherwise
  compiles the React code with Hono JSX and crashes the page.
- `@cloudflare/workers-types` must be v5 to satisfy wrangler's peer dependency.
- The dev server runs on whichever machine you start it on; `localhost:3000` isn't reachable from elsewhere.
- Vite caches transforms; if config changes seem ignored, restart with `npm run dev -- --force`.
