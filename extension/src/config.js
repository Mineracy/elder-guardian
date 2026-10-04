export const API_BASE = 'https://guardian-backend.rowdyhacks.workers.dev';

// For local development, point the extension at your dev server from the service worker console:
//   chrome.storage.local.set({ apiBase: 'http://localhost:3000' })
// and remove it again with chrome.storage.local.remove('apiBase').
export async function resolveApiBase() {
  try {
    const { apiBase } = await chrome.storage.local.get('apiBase');
    if (typeof apiBase === 'string' && /^https?:\/\//.test(apiBase)) return apiBase.replace(/\/+$/, '');
  } catch {
    /* storage unavailable: use the default */
  }
  return API_BASE;
}
