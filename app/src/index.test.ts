import test from 'node:test'
import assert from 'node:assert/strict'

import app from './index.js'

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
