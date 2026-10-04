import { API_BASE, resolveApiBase } from './config.js';
import {
  apiFetch, getSession, grantPass, hasPass, hostOf, isWhitelisted, refreshWhitelist,
} from './api.js';

const DANGEROUS_DOWNLOADS = [/anydesk/i, /teamviewer/i, /rustdesk/i, /screenconnect/i];
const BACKEND_HOST = hostOf(API_BASE);

function holdUrl({ target, trigger, context, kind = 'navigate' }) {
  const params = new URLSearchParams({ target, trigger, kind });
  if (context) params.set('context', context.slice(0, 300));
  return chrome.runtime.getURL(`src/hold.html?${params}`);
}

async function isProtected() {
  const session = await getSession();
  return session?.role === 'protected';
}

// Detection engine: any top-level navigation to a domain outside the whitelist is held.
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0 || !/^https?:/.test(details.url)) return;

  const session = await getSession();
  if (!session || session.role !== 'protected') {
    console.debug('[guardian] skipping block: not a protected session');
    return;
  }

  const host = hostOf(details.url);
  const backendHost = hostOf(await resolveApiBase());
  if (!host || host === backendHost) return;
  if (await hasPass(details.url)) return;

  const { whitelist = [] } = await chrome.storage.local.get('whitelist');
  if (isWhitelisted(host, whitelist)) return;

  console.log('[guardian] holding blocked page', { url: details.url, host, trigger: 'NON_WHITELISTED_DOMAIN' });
  chrome.tabs.update(details.tabId, {
    url: holdUrl({ target: details.url, trigger: 'NON_WHITELISTED_DOMAIN' }),
  });
});

// Dangerous remote-access tool downloads are cancelled and sent for approval.
chrome.downloads.onCreated.addListener(async (item) => {
  if (!(await isProtected())) return;
  if (!DANGEROUS_DOWNLOADS.some((re) => re.test(item.filename || item.url))) return;
  chrome.downloads.cancel(item.id);
  chrome.downloads.erase({ id: item.id });
  chrome.tabs.create({
    url: holdUrl({ target: item.finalUrl || item.url, trigger: 'DANGEROUS_REMOTE_TOOL_DOWNLOAD', kind: 'download' }),
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const run = async () => {
    switch (message.action) {
      case 'SCAM_CONTENT': {
        // Fake tech-support pages are held even on otherwise-allowed domains.
        const url = sender.tab?.url;
        if (!sender.tab || !url || !(await isProtected()) || (await hasPass(url))) return {};
        chrome.tabs.update(sender.tab.id, {
          url: holdUrl({ target: url, trigger: 'FAKE_TECH_SUPPORT_POPUP', context: message.phrase }),
        });
        return {};
      }
      case 'CREATE_INTERVENTION':
        return apiFetch('/api/interventions', { method: 'POST', body: message.payload });
      case 'GET_INTERVENTION':
        return apiFetch(`/api/interventions/${encodeURIComponent(message.id)}`);
      case 'RELEASE':
        await grantPass(message.target);
        await refreshWhitelist().catch(() => {}); // picks up "always allow"
        return {};
      default:
        return {};
    }
  };
  run().then(sendResponse, (err) => sendResponse({ error: err.message }));
  return true;
});

chrome.runtime.onStartup.addListener(() => refreshWhitelist().catch(() => {}));
