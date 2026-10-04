import assert from 'node:assert/strict'
import test from 'node:test'

import { analyzeUrl, maxLevel } from './signals'

const codes = (url: string) => analyzeUrl(url).signals.map((s) => s.code)

test('flags lookalike and brand impersonation domains', () => {
  assert.ok(codes('https://paypa1-secure-login.xyz/verify').includes('BRAND_IMPERSONATION'))
  assert.ok(codes('https://amaz0n.com/deal').includes('BRAND_IMPERSONATION'))
  assert.ok(codes('https://paypal.com.account-check.top/').includes('BRAND_IMPERSONATION'))
  assert.ok(codes('https://microsoft-support-helpdesk.com/').includes('BRAND_IMPERSONATION'))
  assert.ok(codes('https://irs-refund.net/').includes('BRAND_IMPERSONATION'))
  assert.equal(analyzeUrl('https://paypa1-secure-login.xyz/verify').floor, 'HIGH')
})

test('does not flag real brand sites or innocent look-alikes', () => {
  for (const url of [
    'https://www.paypal.com/signin',
    'https://smile.amazon.com/',
    'https://support.microsoft.com/help',
    'https://mail.google.com/',
    'https://www.wikipedia.org/',
    'https://first-ups.example.org/',
    'https://groups.example.com/',
  ]) {
    assert.deepEqual(codes(url).filter((c) => c === 'BRAND_IMPERSONATION'), [], url)
  }
  assert.equal(analyzeUrl('https://www.paypal.com/signin').floor, null)
})

test('flags structural red flags', () => {
  assert.ok(codes('https://xn--pypal-4ve.com/').includes('PUNYCODE_LOOKALIKE'))
  assert.ok(codes('http://185.23.4.9/login').includes('IP_ADDRESS_HOST'))
  assert.ok(codes('https://google.com@evil.example/').includes('HIDDEN_USERINFO'))
  assert.ok(codes('https://bit.ly/3abc').includes('URL_SHORTENER'))
  assert.ok(codes('https://deals.example.click/').includes('SUSPICIOUS_TLD'))
  assert.ok(codes('https://example.com/setup.exe').includes('INSTALLER_DOWNLOAD'))
  assert.ok(codes('https://example.com/buy-gift-card').includes('PAYMENT_KEYWORDS'))
  assert.ok(codes('http://example.com/').includes('NOT_ENCRYPTED'))
  assert.ok(codes('https://a.b.c.d.example.com/').includes('MANY_SUBDOMAINS'))
})

test('ignores local development addresses and invalid input', () => {
  assert.deepEqual(analyzeUrl('http://127.0.0.1:4000/ok').signals, [])
  assert.deepEqual(analyzeUrl('http://localhost:3000/').signals, [])
  assert.deepEqual(analyzeUrl('http://192.168.1.10/').signals, [])
  assert.deepEqual(analyzeUrl('not a url'), { signals: [], floor: null })
})

test('maxLevel keeps the more severe level', () => {
  assert.equal(maxLevel('LOW', 'HIGH'), 'HIGH')
  assert.equal(maxLevel('CRITICAL', 'MEDIUM'), 'CRITICAL')
  assert.equal(maxLevel('MEDIUM', 'MEDIUM'), 'MEDIUM')
})
