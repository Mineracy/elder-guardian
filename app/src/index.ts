import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { ContentfulStatusCode } from 'hono/utils/http-status'
import { generateAnalysis, SYSTEM_INSTRUCTION } from './gemini'
import auth, { verify } from './routes/auth'
import guardian from './routes/guardian'
import interventions from './routes/interventions'
import review from './routes/review'
import settings from './routes/settings'
import type { AppEnv } from './types'

const app = new Hono<AppEnv>()

app.use(
  '/api/*',
  cors({
    // The website is same-origin; only the extension (and local tooling) call across origins.
    origin: (origin) =>
      origin.startsWith('chrome-extension://') || origin.startsWith('http://localhost') ? origin : null,
    allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
  }),
)

app.route('/api/auth', auth)
app.route('/api/guardian', guardian)
app.route('/api', settings)
app.route('/api/interventions', interventions)
app.route('/review', review)
app.route('/verify', verify)

app.get('/health', (c) => c.json({ ok: true, service: 'guardian-backend' }))

app.get('/test', async (c) => {
  const env = {
    GEMINI_API_KEY: c.env?.GEMINI_API_KEY ?? process.env.GEMINI_API_KEY,
    GEMINI_MODEL: c.env?.GEMINI_MODEL ?? process.env.GEMINI_MODEL,
  }

  // Same client, schema and prompt as real interventions, so a passing /test means interventions work too.
  const result = await generateAnalysis(env, {
    system: SYSTEM_INSTRUCTION,
    event: JSON.stringify({
      url: 'https://paypa1-secure-login.xyz/verify',
      domain: 'paypa1-secure-login.xyz',
      trigger: 'DEBUG_TEST',
      signals: ['Uses the name "PayPal" but is not PayPal\'s real website'],
      page_context: 'This is a Gemini debug probe from the public /test route.',
    }),
  })

  if (result.ok) {
    return c.json(
      { ok: true, status: 200, model: result.model, latencyMs: result.latencyMs, message: 'Gemini is working', analysis: result.analysis },
      200,
    )
  }
  return c.json(
    {
      ok: false,
      status: result.status,
      model: result.model,
      latencyMs: result.latencyMs,
      message: result.message,
      ...(result.rawError ? { rawError: result.rawError } : {}),
      ...(result.rawResponse ? { rawResponse: result.rawResponse } : {}),
    },
    result.status as ContentfulStatusCode,
  )
})

export default app
