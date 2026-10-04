import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { parseAnalysis } from './gemini'
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
  const key = c.env?.GEMINI_API_KEY ?? process.env.GEMINI_API_KEY
  const model = c.env?.GEMINI_MODEL ?? process.env.GEMINI_MODEL ?? 'gemini-3.5-flash-lite'

  if (!key) {
    return c.json(
      {
        ok: false,
        status: 500,
        model,
        message: 'GEMINI_API_KEY is missing on the deployed Worker. Set it with `npx wrangler secret put GEMINI_API_KEY --name guardian-backend`.',
      },
      500,
    )
  }

  const event = JSON.stringify({
    url: 'https://example.com/fake-tech-support',
    domain: 'example.com',
    trigger: 'DEBUG_TEST',
    page_context: 'This is a Gemini debug probe from the public /test route.',
  })

  try {
    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': key,
        },
        body: JSON.stringify({
          systemInstruction: {
            parts: [{ text: 'Return JSON only with keys threat_level, risk_summary, user_education_message, trusted_contact_alert.' }],
          },
          contents: [{ role: 'user', parts: [{ text: `<event>${event}</event>` }] }],
          generationConfig: {
            temperature: 0.2,
            responseMimeType: 'application/json',
            responseSchema: {
              type: 'OBJECT',
              properties: {
                threat_level: { type: 'STRING' },
                risk_summary: { type: 'STRING' },
                user_education_message: { type: 'STRING' },
                trusted_contact_alert: { type: 'STRING' },
              },
              required: ['threat_level', 'risk_summary', 'user_education_message', 'trusted_contact_alert'],
            },
          },
        }),
      },
    )

    const raw = await res.text()
    let json: any = null
    try { json = JSON.parse(raw) } catch {}

    if (!res.ok) {
      const apiMessage = (json?.error?.message ?? raw.slice(0, 500)) || 'Unknown Gemini API error'
      return c.json(
        {
          ok: false,
          status: res.status,
          model,
          message: `Gemini rejected the request. Check the API key, model name, and quota. Response: ${apiMessage}`,
          rawError: apiMessage,
        },
        res.status as any,
      )
    }

    const candidateTexts = (json?.candidates ?? [])
      .flatMap((candidate: any) => candidate.content?.parts ?? [])
      .map((part: any) => part.text)
      .filter((text: unknown): text is string => typeof text === 'string' && text.trim().length > 0)

    const parsedCandidates = candidateTexts.map(parseAnalysis)
    const analysis = parsedCandidates.find(Boolean) ?? null

    if (!analysis) {
      return c.json(
        {
          ok: false,
          status: 502,
          model,
          message: 'Gemini returned a response but it was not valid JSON. This usually means the model output was malformed or wrapped in markdown fences.',
          rawResponse: raw.slice(0, 750),
        },
        502,
      )
    }

    return c.json({ ok: true, status: 200, model, message: 'Gemini is working', analysis }, 200)
  } catch (error) {
    const message = error instanceof Error ? error.message : 'Unknown error while calling Gemini'
    return c.json(
      {
        ok: false,
        status: 500,
        model,
        message: `Gemini call failed: ${message}`,
      },
      500,
    )
  }
})

export default app
