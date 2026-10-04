import assert from 'node:assert/strict'
import test from 'node:test'

import { analyzeThreat, generateAnalysis } from './gemini'

const GOOD = {
  threat_level: 'HIGH',
  risk_summary: 'Looks like a PayPal lookalike.',
  user_education_message: 'We paused this page because the address is odd.',
  trusted_contact_alert: 'They tried to open a suspicious page.',
}
const ok = (text: string) =>
  new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text }] } }] }), { status: 200 })
const err = (status: number, message: string) => new Response(JSON.stringify({ error: { message } }), { status })

const ctx = {
  targetUrl: 'https://paypa1-secure-login.xyz/verify',
  domain: 'paypa1-secure-login.xyz',
  triggerType: 'NON_WHITELISTED_DOMAIN',
  protectedEmail: 'a@example.com',
  signals: ['Uses the name "PayPal" but is not PayPal\'s real website'],
}

/** Runs `fn` with fetch replaced by a scripted sequence of responses; returns the request bodies it saw. */
async function withFetch(script: (Response | Error)[], fn: () => Promise<void>) {
  const original = globalThis.fetch
  const bodies: any[] = []
  globalThis.fetch = (async (_url: unknown, init?: RequestInit) => {
    bodies.push(JSON.parse(String(init?.body)))
    const next = script.shift()
    if (!next) throw new Error('unexpected extra Gemini call')
    if (next instanceof Error) throw next
    return next
  }) as typeof fetch
  try {
    await fn()
  } finally {
    globalThis.fetch = original
  }
  return bodies
}

const timeout = () => Object.assign(new Error('timed out'), { name: 'TimeoutError' })

test('succeeds and sends the structured-output config', async () => {
  const bodies = await withFetch([ok(JSON.stringify(GOOD))], async () => {
    const r = await analyzeThreat({ GEMINI_API_KEY: 'k' } as any, ctx)
    assert.equal(r.usedFallback, false)
    assert.equal(r.analysis.threat_level, 'HIGH')
  })
  assert.equal(bodies.length, 1)
  assert.equal(bodies[0].generationConfig.temperature, 0.2)
  assert.ok(bodies[0].generationConfig.responseSchema)
  assert.match(bodies[0].contents[0].parts[0].text, /signals/)
})

test('retries without responseSchema when the API rejects the schema', async () => {
  const bodies = await withFetch([err(400, 'Invalid JSON payload: unknown field "enum"'), ok(JSON.stringify(GOOD))], async () => {
    const r = await generateAnalysis({ GEMINI_API_KEY: 'k' }, { system: 's', event: '{}' })
    assert.equal(r.ok, true)
  })
  assert.equal(bodies.length, 2)
  assert.ok(bodies[0].generationConfig.responseSchema)
  assert.equal(bodies[1].generationConfig.responseSchema, undefined)
})

test('does not retry a bad API key and falls back with the reason recorded', async () => {
  const bodies = await withFetch([err(400, 'API key not valid. Please pass a valid API key.')], async () => {
    const r = await analyzeThreat({ GEMINI_API_KEY: 'bad' } as any, ctx)
    assert.equal(r.usedFallback, true)
    assert.equal(r.analysis.threat_level, 'MEDIUM')
    assert.match(r.aiError ?? '', /API key not valid/)
    assert.match(r.analysis.risk_summary, /Red flags: .*PayPal/)
  })
  assert.equal(bodies.length, 1)
})

test('retries once on a transient 503 and on a timeout', async () => {
  await withFetch([err(503, 'overloaded'), ok(JSON.stringify(GOOD))], async () => {
    assert.equal((await generateAnalysis({ GEMINI_API_KEY: 'k' }, { system: 's', event: '{}' })).ok, true)
  })
  await withFetch([timeout(), ok(JSON.stringify(GOOD))], async () => {
    assert.equal((await generateAnalysis({ GEMINI_API_KEY: 'k' }, { system: 's', event: '{}' })).ok, true)
  })
})

test('gives up after repeated timeouts with a 504', async () => {
  await withFetch([timeout(), timeout()], async () => {
    const r = await generateAnalysis({ GEMINI_API_KEY: 'k' }, { system: 's', event: '{}' })
    assert.equal(r.ok, false)
    assert.equal(r.status, 504)
  })
})

test('accepts fenced JSON and rejects unusable output', async () => {
  await withFetch([ok('```json\n' + JSON.stringify(GOOD) + '\n```')], async () => {
    assert.equal((await generateAnalysis({ GEMINI_API_KEY: 'k' }, { system: 's', event: '{}' })).ok, true)
  })
  await withFetch([ok('not json'), ok('still not json')], async () => {
    const r = await generateAnalysis({ GEMINI_API_KEY: 'k' }, { system: 's', event: '{}' })
    assert.equal(r.ok, false)
    assert.equal(r.status, 502)
  })
  await withFetch([ok(JSON.stringify({ ...GOOD, threat_level: 'SEVERE' })), ok(JSON.stringify({ ...GOOD, threat_level: 'SEVERE' }))], async () => {
    assert.equal((await generateAnalysis({ GEMINI_API_KEY: 'k' }, { system: 's', event: '{}' })).ok, false)
  })
})

test('reports a missing key without calling Gemini', async () => {
  const bodies = await withFetch([], async () => {
    const r = await analyzeThreat({} as any, ctx)
    assert.equal(r.usedFallback, true)
    assert.match(r.aiError ?? '', /GEMINI_API_KEY is missing/)
  })
  assert.equal(bodies.length, 0)
})
