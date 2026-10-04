import { resolveApiBase } from './config.js';

const PASS_TTL_MS = 30 * 60 * 1000;

export async function getSession() {
  const { session } = await chrome.storage.local.get('session');
  return session ?? null;
}

export async function apiFetch(path, { method = 'GET', body, auth = true } = {}) {
  const base = await resolveApiBase();
  const headers = { 'Content-Type': 'application/json' };
  if (auth) {
    const session = await getSession();
    if (!session) throw new Error('Not signed in');
    headers.Authorization = `Bearer ${session.token}`;
  }
  const res = await fetch(`${base}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });

  // Read the body once as text: a failed res.json() consumes it, which used to turn every non-JSON
  // server error (e.g. a 500 page) into "Unknown error" and hide the real reason.
  const raw = await res.text().catch(() => '');
  let data = {};
  try {
    data = raw ? JSON.parse(raw) : {};
  } catch {
    data = { error: raw ? `Server error (${res.status}): ${raw.slice(0, 120)}` : `Server error (${res.status})` };
  }

  if (res.status === 401 && auth) await chrome.storage.local.remove('session');
  if (!res.ok) {
    const msg = data?.error || data?.message || `Request failed (${res.status})`;
    throw new Error(msg);
  }
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
  await chrome.storage.local.remove(['session', 'whitelist', 'whitelistFetchedAt', 'passes', 'policy', 'txApproved']);
}

// Guardians can edit the whitelist at any time, so the local copy is refreshed regularly.
export const WHITELIST_STALE_MS = 30 * 1000;

// The guardian's transaction limit; the transaction watcher (transactions.js) reads it from storage.
export async function refreshPolicy() {
  const { transactionLimit } = await apiFetch('/api/policy');
  const backendHost = hostOf(await resolveApiBase());
  await chrome.storage.local.set({ policy: { transactionLimit, backendHost } });
}

// Refreshes everything the guardian controls (whitelist and policy) so edits reach this browser quickly.
export async function refreshWhitelist() {
  const { domains } = await apiFetch('/api/whitelist');
  await chrome.storage.local.set({
    whitelist: domains.map((d) => d.domain),
    whitelistFetchedAt: Date.now(),
  });
  await refreshPolicy().catch(() => {});
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
