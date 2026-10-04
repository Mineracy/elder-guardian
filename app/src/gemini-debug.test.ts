import assert from 'node:assert/strict'
import test from 'node:test'

import app from './index.js'

test('gemini debug endpoint returns a clear status payload', async () => {
  const originalFetch = globalThis.fetch
  const originalApiKey = process.env.GEMINI_API_KEY
  const originalModel = process.env.GEMINI_MODEL

  process.env.GEMINI_API_KEY = 'test-key'
  process.env.GEMINI_MODEL = 'gemini-2.5-flash'

  globalThis.fetch = async () =>
    new Response(JSON.stringify({ error: { message: 'API key not valid' } }), { status: 400 }) as Response

  try {
    const res = await app.request('http://localhost/test')
    const json = (await res.json()) as { ok: boolean; status: number; message: string; model: string }

    assert.equal(res.status, 400)
    assert.equal(json.ok, false)
    assert.match(json.message, /API key not valid|invalid|key/i)
    assert.equal(json.model, 'gemini-2.5-flash')
  } finally {
    globalThis.fetch = originalFetch
    if (originalApiKey === undefined) delete process.env.GEMINI_API_KEY
    else process.env.GEMINI_API_KEY = originalApiKey

    if (originalModel === undefined) delete process.env.GEMINI_MODEL
    else process.env.GEMINI_MODEL = originalModel
  }
})
