import type { ThreatLevel } from './types'

export type Signal = { code: string; label: string; severity: 'MEDIUM' | 'HIGH' }

const LEVEL_ORDER: ThreatLevel[] = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']

export const maxLevel = (a: ThreatLevel, b: ThreatLevel): ThreatLevel =>
  LEVEL_ORDER.indexOf(a) >= LEVEL_ORDER.indexOf(b) ? a : b

/** Minimum threat level implied by what the extension detected, whatever the AI says. */
export const TRIGGER_FLOORS: Record<string, ThreatLevel> = {
  NON_WHITELISTED_DOMAIN: 'MEDIUM',
  FAKE_TECH_SUPPORT_POPUP: 'HIGH',
  DANGEROUS_REMOTE_TOOL_DOWNLOAD: 'HIGH',
  SUSPICIOUS_DOWNLOAD: 'MEDIUM',
  GIFT_CARD_PAYMENT: 'HIGH',
  GOV_IMPERSONATION_THREAT: 'HIGH',
  ACCOUNT_VERIFICATION_PHISH: 'HIGH',
  PRIZE_OR_LOTTERY: 'MEDIUM',
  INSECURE_LOGIN_FORM: 'MEDIUM',
  LARGE_PAYMENT_FORM: 'MEDIUM',
}

const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'click', 'gq', 'tk', 'ml', 'cf', 'ga', 'work', 'zip', 'mov', 'rest', 'country', 'kim',
  'loan', 'men', 'party', 'review', 'stream', 'win', 'bid', 'icu', 'cyou', 'buzz', 'monster', 'cfd', 'sbs',
])

const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly',
  'shorturl.at', 'tiny.cc', 'rb.gy',
])

const FREE_HOSTING = [
  'blogspot.com', 'weebly.com', 'wixsite.com', 'netlify.app', 'pages.dev', 'web.app', 'firebaseapp.com',
  'glitch.me', 'ngrok.io', 'trycloudflare.com', 'duckdns.org', 'github.io',
]

const INSTALLER_EXT = /\.(exe|msi|scr|bat|cmd|apk|dmg|pkg|jar|vbs|ps1|iso|hta)$/i

const LOGIN_WORDS = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'billing', 'helpdesk', 'unlock', 'refund', 'prize', 'suspended']
const MONEY_WORDS = /(gift-?card|bitcoin|\bbtc\b|crypto|wire-?transfer)/i

/** Brands scammers impersonate, with the registrable domains that are really theirs. */
const BRANDS: Record<string, { name: string; official: string[] }> = {
  paypal: { name: 'PayPal', official: ['paypal.com', 'paypal.me'] },
  amazon: { name: 'Amazon', official: ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.de', 'amazon.fr', 'amazon.es', 'amazon.it', 'amazon.in', 'amazon.com.au', 'amazon.co.jp', 'amazonaws.com', 'a.co'] },
  microsoft: { name: 'Microsoft', official: ['microsoft.com', 'live.com', 'office.com', 'outlook.com', 'windows.com', 'msn.com', 'bing.com'] },
  apple: { name: 'Apple', official: ['apple.com', 'icloud.com'] },
  google: { name: 'Google', official: ['google.com', 'gmail.com', 'youtube.com', 'goo.gl', 'google.co.uk', 'googleapis.com'] },
  netflix: { name: 'Netflix', official: ['netflix.com'] },
  facebook: { name: 'Facebook', official: ['facebook.com', 'fb.com', 'messenger.com'] },
  instagram: { name: 'Instagram', official: ['instagram.com'] },
  whatsapp: { name: 'WhatsApp', official: ['whatsapp.com', 'whatsapp.net'] },
  chase: { name: 'Chase', official: ['chase.com'] },
  wellsfargo: { name: 'Wells Fargo', official: ['wellsfargo.com'] },
  bankofamerica: { name: 'Bank of America', official: ['bankofamerica.com', 'bofa.com'] },
  citibank: { name: 'Citibank', official: ['citibank.com', 'citi.com'] },
  capitalone: { name: 'Capital One', official: ['capitalone.com'] },
  americanexpress: { name: 'American Express', official: ['americanexpress.com', 'amex.com'] },
  venmo: { name: 'Venmo', official: ['venmo.com'] },
  zelle: { name: 'Zelle', official: ['zellepay.com'] },
  cashapp: { name: 'Cash App', official: ['cash.app', 'cashapp.com'] },
  coinbase: { name: 'Coinbase', official: ['coinbase.com'] },
  binance: { name: 'Binance', official: ['binance.com', 'binance.us'] },
  walmart: { name: 'Walmart', official: ['walmart.com'] },
  ebay: { name: 'eBay', official: ['ebay.com'] },
  fedex: { name: 'FedEx', official: ['fedex.com'] },
  usps: { name: 'USPS', official: ['usps.com'] },
  ups: { name: 'UPS', official: ['ups.com'] },
  dhl: { name: 'DHL', official: ['dhl.com'] },
  irs: { name: 'the IRS', official: ['irs.gov'] },
  medicare: { name: 'Medicare', official: ['medicare.gov'] },
  norton: { name: 'Norton', official: ['norton.com'] },
  mcafee: { name: 'McAfee', official: ['mcafee.com'] },
  geeksquad: { name: 'Geek Squad', official: ['geeksquad.com', 'bestbuy.com'] },
  docusign: { name: 'DocuSign', official: ['docusign.com', 'docusign.net'] },
}
// Shorter brand names are matched more strictly (see impersonatedBrand).
const MIN_SUBSTRING_LEN = 5

const SECOND_LEVEL = new Set(['co', 'com', 'org', 'net', 'gov', 'ac', 'edu'])

function registrableDomain(host: string): string {
  const parts = host.split('.')
  if (parts.length <= 2) return host
  const tld = parts[parts.length - 1]
  const sld = parts[parts.length - 2]
  return tld.length === 2 && SECOND_LEVEL.has(sld) ? parts.slice(-3).join('.') : parts.slice(-2).join('.')
}

function isPrivateOrLoopback(host: string): boolean {
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local')) return true
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/)
  if (!m) return host.startsWith('[') && (host === '[::1]' || host.toLowerCase().startsWith('[fe80') || host.toLowerCase().startsWith('[fc') || host.toLowerCase().startsWith('[fd'))
  const [a, b] = [Number(m[1]), Number(m[2])]
  return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254)
}

/** Undo common character swaps used in lookalike domains (paypa1, amaz0n, rn -> m). */
function lookalikeVariants(token: string): string[] {
  const base = token.replace(/rn/g, 'm').replace(/vv/g, 'w').replace(/0/g, 'o').replace(/3/g, 'e').replace(/5/g, 's').replace(/4/g, 'a').replace(/\$/g, 's')
  return [base.replace(/1/g, 'l'), base.replace(/1/g, 'i')]
}

function editDistanceAtMostOne(a: string, b: string): boolean {
  if (Math.abs(a.length - b.length) > 1) return false
  let i = 0
  while (i < a.length && i < b.length && a[i] === b[i]) i++
  if (i === a.length || i === b.length) return true
  if (a.length === b.length && a.slice(i + 1) === b.slice(i + 1)) return true
  if (a.length === b.length + 1 && a.slice(i + 1) === b.slice(i)) return true
  if (b.length === a.length + 1 && b.slice(i + 1) === a.slice(i)) return true
  return false
}

/** Does this hostname impersonate a known brand it doesn't belong to? Returns the brand's display name. */
function impersonatedBrand(host: string): string | null {
  const reg = registrableDomain(host)
  const dotLabels = host.split('.')
  const tokens = host.split(/[.-]/).filter(Boolean)
  const hasLoginWord = tokens.some((t) => LOGIN_WORDS.includes(t))
  const compact = host.replace(/[^a-z0-9]/g, '')

  for (const [key, brand] of Object.entries(BRANDS)) {
    if (brand.official.includes(reg) || brand.official.some((d) => host.endsWith(`.${d}`))) continue

    // Short names ("ups", "irs") are common word fragments, so they need a whole label or a login-style companion word.
    const exactToken = key.length >= MIN_SUBSTRING_LEN ? tokens.includes(key) : dotLabels.includes(key) || (tokens.includes(key) && hasLoginWord)
    const substring = key.length >= MIN_SUBSTRING_LEN && compact.includes(key)
    const lookalike = key.length >= MIN_SUBSTRING_LEN && tokens.some((t) => t !== key && (lookalikeVariants(t).includes(key) || (t.length >= 6 && editDistanceAtMostOne(t, key))))
    if (exactToken || substring || lookalike) return brand.name
  }
  return null
}

/** Heuristic checks on a URL alone. Deterministic, so it also works when the AI is down. */
export function analyzeUrl(rawUrl: string): { signals: Signal[]; floor: ThreatLevel | null } {
  let url: URL
  try {
    url = new URL(rawUrl)
  } catch {
    return { signals: [], floor: null }
  }

  const signals: Signal[] = []
  const add = (code: string, label: string, severity: Signal['severity']) => signals.push({ code, label, severity })

  const host = url.hostname.toLowerCase().replace(/\.$/, '')
  const privateHost = isPrivateOrLoopback(host)
  const labels = host.split('.')
  const tld = labels[labels.length - 1]
  const reg = registrableDomain(host)
  const sld = labels.length >= 2 ? labels[labels.length - (reg.split('.').length)] ?? '' : host

  if (url.username || url.password) add('HIDDEN_USERINFO', 'The link hides its real destination with an "@" trick', 'HIGH')
  if (labels.some((l) => l.startsWith('xn--'))) add('PUNYCODE_LOOKALIKE', 'The address uses look-alike international characters', 'HIGH')
  if (!privateHost && (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.startsWith('[') || /^0x[0-9a-f]+$/i.test(host) || /^\d{8,10}$/.test(host))) {
    add('IP_ADDRESS_HOST', 'The address is a raw number instead of a company name', 'HIGH')
  }
  if (!privateHost && SUSPICIOUS_TLDS.has(tld)) add('SUSPICIOUS_TLD', `Ends in ".${tld}", which scam sites use a lot`, 'MEDIUM')
  if (SHORTENERS.has(reg)) add('URL_SHORTENER', 'A shortened link that hides where it really goes', 'MEDIUM')
  if (FREE_HOSTING.some((d) => host === d || host.endsWith(`.${d}`))) add('FREE_HOSTING', 'Hosted on a free website service rather than a company site', 'MEDIUM')

  if (!privateHost) {
    const brand = impersonatedBrand(host)
    if (brand) add('BRAND_IMPERSONATION', `Uses the name "${brand}" but is not ${brand}'s real website`, 'HIGH')
  }

  if (!privateHost) {
    const hyphens = (sld.match(/-/g) ?? []).length
    const hasLoginWord = LOGIN_WORDS.some((w) => host.split(/[.-]/).includes(w))
    if (hasLoginWord) add('LOGIN_KEYWORDS', 'The address looks like a "log in / verify your account" page', 'MEDIUM')
    else if (hyphens >= 2) add('MANY_HYPHENS', 'The address is stuffed with hyphens, a common scam pattern', 'MEDIUM')
    if (labels.length >= 5) add('MANY_SUBDOMAINS', 'The address has an unusually long chain of sub-sites', 'MEDIUM')
  }

  if (INSTALLER_EXT.test(url.pathname)) add('INSTALLER_DOWNLOAD', 'The link downloads a program installer', 'HIGH')
  if (MONEY_WORDS.test(url.hostname + url.pathname)) add('PAYMENT_KEYWORDS', 'The address mentions gift cards, crypto or wire transfers', 'MEDIUM')
  if (url.protocol === 'http:' && !privateHost) add('NOT_ENCRYPTED', 'The connection is not encrypted (http, not https)', 'MEDIUM')

  const floor = signals.length === 0 ? null : signals.some((s) => s.severity === 'HIGH') ? 'HIGH' : 'MEDIUM'
  return { signals, floor }
}
