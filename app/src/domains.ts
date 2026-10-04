/** Normalise a hostname or URL to a bare lowercase domain without "www.". Returns null if invalid. */
export function normalizeDomain(input: string): string | null {
  const raw = input.trim().toLowerCase()
  if (!raw) return null
  let host: string
  try {
    host = new URL(raw.includes('://') ? raw : `https://${raw}`).hostname
  } catch {
    return null
  }
  host = host.replace(/^www\./, '').replace(/\.$/, '')
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(host) ? host : null
}

/** Domains every new protected account starts with so everyday browsing isn't interrupted. */
export const DEFAULT_WHITELIST = [
  'google.com',
  'youtube.com',
  'gmail.com',
  'wikipedia.org',
  'weather.com',
  'facebook.com',
]
