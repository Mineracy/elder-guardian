import { API_BASE } from './config.js';

const PASS_TTL_MS = 30 * 60 * 1000;

export async function getSession() {
  const { session } = await chrome.storage.local.get('session');
  return session ?? null;
}

export async function apiFetch(path, { method = 'GET', body, auth = true } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (auth) {
    const session = await getSession();
    if (!session) throw new Error('Not signed in');
    headers.Authorization = `Bearer ${session.token}`;
  }
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && auth) await chrome.storage.local.remove('session');
  if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
  return data;
}

export async function authenticate(mode, email, password, role) {
  const data = await apiFetch(mode === 'signup' ? '/api/auth/signup' : '/api/auth/signin', {
    method: 'POST',
    auth: false,
    body: { email, password, role },
  });
  await chrome.storage.local.set({ session: { token: data.token, ...data.user } });
  if (data.user.role === 'protected') await refreshWhitelist();
  return data.user;
}

export async function signOut() {
  await chrome.storage.local.remove(['session', 'whitelist', 'passes']);
}

export async function refreshWhitelist() {
  const { domains } = await apiFetch('/api/whitelist');
  await chrome.storage.local.set({ whitelist: domains.map((d) => d.domain) });
  return domains;
}

export function hostOf(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '').toLowerCase();
  } catch {
    return null;
  }
}

export function isWhitelisted(host, whitelist) {
  return whitelist.some((d) => host === d || host.endsWith(`.${d}`));
}

// A trusted contact's "Allow" is remembered briefly so the released page isn't intercepted again.
export async function grantPass(url) {
  const { passes = {} } = await chrome.storage.local.get('passes');
  const now = Date.now();
  for (const k of Object.keys(passes)) if (passes[k] < now) delete passes[k];
  passes[url] = now + PASS_TTL_MS;
  await chrome.storage.local.set({ passes });
}

export async function hasPass(url) {
  const { passes = {} } = await chrome.storage.local.get('passes');
  return (passes[url] ?? 0) > Date.now();
}
