import test from 'node:test'
import assert from 'node:assert/strict'

import app from './index.js'

test('health endpoint returns ok', async () => {
  const res = await app.request('http://localhost/health')
  assert.equal(res.status, 200)

  const json = await res.json()
  assert.equal(json.ok, true)
  assert.equal(json.service, 'guardian-agent')
})

test('signup and alert pipeline work', async () => {
  const signupRes = await app.request('http://localhost/api/signup', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email: 'alice@example.com',
      password: 'secret123',
      role: 'protected',
    }),
  })

  const signupJson = await signupRes.json()
  assert.equal(signupRes.status, 200)
  assert.equal(signupJson.ok, true)

  const alertRes = await app.request('http://localhost/api/alerts', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      url: 'https://fake-tech-support.example',
      userEmail: 'alice@example.com',
      threatType: 'FAKE_TECH_SUPPORT_POPUP',
      pageText: 'call microsoft support now',
    }),
  })

  const alertJson = await alertRes.json()
  assert.equal(alertRes.status, 200)
  assert.equal(alertJson.ok, true)
  assert.ok(alertJson.threat_level)
  assert.ok(alertJson.user_education_message)
})
