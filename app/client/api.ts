const API_BASE = import.meta.env.VITE_API_BASE ?? ''
const TOKEN_KEY = 'guardian.token'

export type User = { id: string; email: string; role: 'protected' | 'trusted'; email_verified: number }
export type Activity = {
  id: string
  target_url: string
  domain: string
  trigger_type: string
  threat_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  risk_summary: string
  status: 'pending' | 'allowed' | 'denied'
  created_at: number
  signals: { code: string; label: string; severity: 'MEDIUM' | 'HIGH' }[]
  /** Transaction amount in dollars, for LARGE_TRANSACTION requests. */
  amount: number | null
  /** True when the AI was unavailable and a standard summary was used instead. */
  ai_fallback: boolean
}
export type TransactionLimit = { amount: number; action: 'approve' | 'warn' }

export type Protectee = {
  id: string
  email: string
  transactionLimit: TransactionLimit | null
  pendingCount: number
  activity: Activity[]
  whitelist: string[]
}

export class ApiError extends Error {
  constructor(message: string, public status: number) {
    super(message)
  }
}

export const getToken = () => {
  try {
    return localStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}
export const setToken = (t: string | null) => {
  try {
    t ? localStorage.setItem(TOKEN_KEY, t) : localStorage.removeItem(TOKEN_KEY)
  } catch {
    /* storage unavailable: session lasts until reload */
  }
}

async function request<T>(path: string, init: { method?: string; body?: unknown } = {}): Promise<T> {
  const token = getToken()
  const res = await fetch(`${API_BASE}${path}`, {
    method: init.method ?? 'GET',
    headers: { 'Content-Type': 'application/json', ...(token && { Authorization: `Bearer ${token}` }) },
    body: init.body ? JSON.stringify(init.body) : undefined,
  })
  const data = await res.json().catch(() => ({}))
  if (!res.ok) throw new ApiError(data.error ?? `Request failed (${res.status})`, res.status)
  return data as T
}

export const api = {
  signUp: (email: string, password: string) =>
    request<{ token: string; user: User; devVerifyUrl?: string }>('/api/auth/signup', {
      method: 'POST',
      body: { email, password, role: 'trusted' },
    }),
  signIn: (email: string, password: string) =>
    request<{ token: string; user: User }>('/api/auth/signin', { method: 'POST', body: { email, password } }),
  me: () => request<{ user: User }>('/api/auth/me'),
  resendVerification: () =>
    request<{ ok: boolean; devVerifyUrl?: string }>('/api/auth/resend-verification', { method: 'POST' }),
  dashboard: () => request<{ protectees: Protectee[] }>('/api/guardian/dashboard'),
  decide: (id: string, decision: 'allow' | 'deny', addToWhitelist: boolean) =>
    request<{ status: string }>(`/api/guardian/interventions/${id}/decision`, {
      method: 'POST',
      body: { decision, addToWhitelist },
    }),
  setTransactionLimit: (protectedId: string, limit: TransactionLimit | null) =>
    request<{ ok: boolean }>(`/api/guardian/protectees/${protectedId}/transaction-limit`, {
      method: 'PUT',
      body: limit ? { amount: limit.amount, action: limit.action } : { amount: null },
    }),
  addWhitelist: (protectedId: string, domain: string) =>
    request<{ ok: boolean; domain: string }>(`/api/guardian/protectees/${protectedId}/whitelist`, {
      method: 'POST',
      body: { domain },
    }),
  removeWhitelist: (protectedId: string, domain: string) =>
    request<{ ok: boolean }>(
      `/api/guardian/protectees/${protectedId}/whitelist/${encodeURIComponent(domain)}`,
      { method: 'DELETE' },
    ),
  removeSelf: (protectedId: string) =>
    request<{ ok: boolean }>(`/api/guardian/protectees/${protectedId}`, { method: 'DELETE' }),
}
