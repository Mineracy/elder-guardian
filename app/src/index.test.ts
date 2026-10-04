import test from 'node:test'
import assert from 'node:assert/strict'

import app from './index.js'
import { analyzeThreat, normalizeGeminiModel } from './gemini.js'

type HealthJson = { ok: boolean; service: string }
type JsonResult = { ok: boolean; service?: string; threat_level?: string; user_education_message?: string }

test('health endpoint returns ok', async () => {
  const res = await app.request('http://localhost/health')
  assert.equal(res.status, 200)

  const json = (await res.json()) as HealthJson
  assert.equal(json.ok, true)
  assert.equal(json.service, 'guardian-backend')
})

test('signup and alert pipeline work', async () => {
  const signupRes = await app.request('http://localhost/api/auth/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'alice@example.com',
      password: 'secret123',
      role: 'protected',
    }),
  })

  const signupJson = (await signupRes.json()) as JsonResult & { token?: string; user?: { role?: string } }
  assert.equal(signupRes.status, 201)
  assert.equal(signupJson.ok, true)

  const alertRes = await app.request('http://localhost/api/interventions', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      targetUrl: 'https://fake-tech-support.example',
      triggerType: 'FAKE_TECH_SUPPORT_POPUP',
      context: 'call microsoft support now',
    }),
  })

  const alertJson = (await alertRes.json()) as JsonResult & { status?: string; userEducationMessage?: string }
  assert.equal(alertRes.status, 201)
  assert.equal(alertJson.status, 'pending')
  assert.ok(alertJson.threat_level || alertJson.userEducationMessage || alertJson.user_education_message)
})

test('trusted guardian can view pending dashboard before verification', async () => {
  const signupRes = await app.request('http://localhost/api/auth/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'guardian-pending@example.com',
      password: 'secret123',
      role: 'trusted',
    }),
  })

  const signupJson = (await signupRes.json()) as { token?: string }
  assert.equal(signupRes.status, 201)
  assert.ok(signupJson.token)

  const dashboardRes = await app.request('http://localhost/api/guardian/dashboard', {
    headers: { Authorization: `Bearer ${signupJson.token}` },
  })

  assert.equal(dashboardRes.status, 200)
  const dashboard = await dashboardRes.json() as { protectees: unknown[] }
  assert.ok(Array.isArray(dashboard.protectees))
})

test('analyzeThreat accepts fenced json responses from Gemini', async () => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () =>
    new Response(JSON.stringify({
      candidates: [
        {
          content: {
            parts: [
              {
                text: '```json\n{\n  "threat_level": "HIGH",\n  "risk_summary": "This is a scam domain.",\n  "user_education_message": "You were paused because this page looked suspicious.",\n  "trusted_contact_alert": "Please review this suspicious site."\n}\n```',
              },
            ],
          },
        },
      ],
    })) as Response

  try {
    const result = await analyzeThreat({ GEMINI_API_KEY: 'valid-key' } as any, {
      targetUrl: 'https://example.com',
      domain: 'example.com',
      triggerType: 'NON_WHITELISTED_DOMAIN',
      protectedEmail: 'user@example.com',
    })

    assert.equal(result.usedFallback, false)
    assert.equal(result.analysis.threat_level, 'HIGH')
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('normalizeGeminiModel handles friendly labels like 3.5 flash lite', () => {
  assert.equal(normalizeGeminiModel('3.5 flash lite'), 'gemini-3.5-flash-lite')
  assert.equal(normalizeGeminiModel('gemini-3.5-flash-lite'), 'gemini-3.5-flash-lite')
  assert.equal(normalizeGeminiModel('gemini-3.8-flash'), 'gemini-3.8-flash')
})

test('gemini debug endpoint returns a clear status payload', async () => {
  const originalFetch = globalThis.fetch
  const originalApiKey = process.env.GEMINI_API_KEY
  const originalModel = process.env.GEMINI_MODEL
  process.env.GEMINI_API_KEY = 'test-key'
  process.env.GEMINI_MODEL = '3.5 flash lite'

  globalThis.fetch = async () =>
    new Response(JSON.stringify({
      error: { message: 'API key not valid' },
    }), { status: 400 }) as Response

  try {
    const res = await app.request('http://localhost/test')
    const json = await res.json() as { ok: boolean; status: number; message: string; model: string }

    assert.equal(res.status, 400)
    assert.equal(json.ok, false)
    assert.match(json.message, /API key not valid|invalid|key/i)
    assert.equal(json.model, 'gemini-3.5-flash-lite')
  } finally {
    globalThis.fetch = originalFetch
    if (originalApiKey === undefined) delete process.env.GEMINI_API_KEY
    else process.env.GEMINI_API_KEY = originalApiKey

    if (originalModel === undefined) delete process.env.GEMINI_MODEL
    else process.env.GEMINI_MODEL = originalModel
  }
})
