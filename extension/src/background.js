import { resolveApiBase } from './config.js';
import {
  apiFetch, getSession, grantPass, hasPass, hostOf, isWhitelisted, refreshWhitelist, WHITELIST_STALE_MS,
} from './api.js';

// Programs scammers talk people into installing so they can take over the computer.
const REMOTE_TOOLS = [
  /anydesk/i, /teamviewer/i, /rustdesk/i, /screenconnect/i, /connectwise/i, /ultraviewer/i, /supremo/i,
  /splashtop/i, /ammyy/i, /logmein/i, /gotoassist/i, /remotepc/i, /aeroadmin/i, /zoho.?assist/i,
];
const INSTALLERS = /\.(exe|msi|scr|bat|cmd|apk|dmg|pkg|jar|vbs|ps1|iso|hta)(?:[?#]|$)/i;

// Triggers the content script may report; anything else is ignored.
const CONTENT_TRIGGERS = new Set([
  'FAKE_TECH_SUPPORT_POPUP', 'GIFT_CARD_PAYMENT', 'GOV_IMPERSONATION_THREAT', 'PRIZE_OR_LOTTERY',
  'ACCOUNT_VERIFICATION_PHISH', 'INSECURE_LOGIN_FORM', 'LARGE_PAYMENT_FORM',
]);

const WHITELIST_ALARM = 'whitelist-refresh';

function holdUrl({ target, trigger, context, kind = 'navigate', back }) {
  const params = new URLSearchParams({ target, trigger, kind });
  if (context) params.set('context', context.slice(0, 300));
  if (back) params.set('back', back); // where "Go back to safety" returns the person to
  return chrome.runtime.getURL(`src/hold.html?${params}`);
}

// Remembers the last two pages each tab committed, so "Go back to safety" can return the person to the
// page they were on before the risky one (history.back() isn't reliable: a scam page that already loaded
// would just be loaded, and held, again).
let trailQueue = Promise.resolve();
function recordCommit(tabId, url) {
  trailQueue = trailQueue.then(async () => {
    const { tabTrail = {} } = await chrome.storage.session.get('tabTrail');
    const t = tabTrail[tabId];
    if (t?.last === url) return;
    tabTrail[tabId] = { prev: t?.last, last: url };
    await chrome.storage.session.set({ tabTrail });
  }).catch(() => {});
  return trailQueue;
}
chrome.webNavigation.onCommitted.addListener((d) => {
  if (d.frameId === 0 && /^https?:/.test(d.url)) recordCommit(d.tabId, d.url);
});
chrome.tabs.onRemoved.addListener((tabId) => {
  trailQueue = trailQueue.then(async () => {
    const { tabTrail = {} } = await chrome.storage.session.get('tabTrail');
    if (tabId in tabTrail) { delete tabTrail[tabId]; await chrome.storage.session.set({ tabTrail }); }
  }).catch(() => {});
});

// The page to send the person back to: the last page they were on, unless that is the held page itself.
async function backTarget(tabId, heldUrl) {
  await trailQueue;
  const { tabTrail = {} } = await chrome.storage.session.get('tabTrail');
  const t = tabTrail[tabId];
  const back = t && t.last !== heldUrl ? t.last : t?.prev;
  return back && /^https?:/.test(back) && back !== heldUrl ? back : undefined;
}

async function isBackendHost(host) {
  return !!host && host === hostOf(await resolveApiBase());
}

async function currentWhitelist() {
  const { whitelist = [], whitelistFetchedAt = 0 } = await chrome.storage.local.get(['whitelist', 'whitelistFetchedAt']);
  return { whitelist, stale: Date.now() - whitelistFetchedAt > WHITELIST_STALE_MS };
}

// Detection engine: any top-level navigation to a domain outside the whitelist is held.
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0 || !/^https?:/.test(details.url)) return;

  const session = await getSession();
  if (!session || session.role !== 'protected') return;

  const host = hostOf(details.url);
  if (!host || (await isBackendHost(host))) return; // never intercept the review/backend pages
  if (await hasPass(details.url)) return;

  let { whitelist, stale } = await currentWhitelist();
  if (isWhitelisted(host, whitelist)) return;

  // Before holding, make sure a guardian hasn't just added this site.
  if (stale) {
    try {
      whitelist = (await refreshWhitelist()).map((d) => d.domain);
    } catch {
      /* offline or signed out: fall through to the cached list */
    }
    if (isWhitelisted(host, whitelist)) return;
  }

  chrome.tabs.update(details.tabId, {
    url: holdUrl({
      target: details.url,
      trigger: 'NON_WHITELISTED_DOMAIN',
      back: await backTarget(details.tabId, details.url),
    }),
  });
});

// Risky downloads are cancelled and sent for approval: remote-access tools anywhere, and program
// installers from sites that aren't on the whitelist.
chrome.downloads.onCreated.addListener(async (item) => {
  const session = await getSession();
  if (!session || session.role !== 'protected') return;

  const url = item.finalUrl || item.url;
  if (!/^https?:/.test(url)) return;
  if ((await hasPass(item.url)) || (await hasPass(url))) return; // already approved by the guardian

  const host = hostOf(url);
  if (!host || (await isBackendHost(host))) return;

  const name = `${item.filename || ''} ${url}`;
  let trigger = null;
  if (REMOTE_TOOLS.some((re) => re.test(name))) {
    trigger = 'DANGEROUS_REMOTE_TOOL_DOWNLOAD';
  } else if (INSTALLERS.test(item.filename || '') || INSTALLERS.test(url)) {
    const { whitelist } = await currentWhitelist();
    if (!isWhitelisted(host, whitelist)) trigger = 'SUSPICIOUS_DOWNLOAD';
  }
  if (!trigger) return;

  chrome.downloads.cancel(item.id);
  chrome.downloads.erase({ id: item.id });
  chrome.tabs.create({ url: holdUrl({ target: url, trigger, kind: 'download' }) });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const run = async () => {
    switch (message.action) {
      case 'SCAM_CONTENT': {
        // Scam-looking pages are held even on otherwise-allowed domains.
        const url = sender.tab?.url;
        if (!sender.tab || !url || !/^https?:/.test(url)) return {};
        const session = await getSession();
        if (session?.role !== 'protected') return {};
        if ((await isBackendHost(hostOf(url))) || (await hasPass(url))) return {};
        const trigger = CONTENT_TRIGGERS.has(message.trigger) ? message.trigger : 'FAKE_TECH_SUPPORT_POPUP';
        chrome.tabs.update(sender.tab.id, {
          url: holdUrl({
            target: url,
            trigger,
            context: String(message.phrase || ''),
            back: await backTarget(sender.tab.id, url),
          }),
        });
        return {};
      }
      case 'CREATE_INTERVENTION':
        return apiFetch('/api/interventions', { method: 'POST', body: message.payload });
      case 'GET_INTERVENTION':
        return apiFetch(`/api/interventions/${encodeURIComponent(message.id)}`);
      case 'GET_POLICY':
        return apiFetch('/api/policy');
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

// Keep the whitelist fresh so guardian edits (adds and removals) reach this browser within a minute.
async function refreshIfProtected() {
  const session = await getSession();
  if (session?.role === 'protected') await refreshWhitelist().catch(() => {});
}
chrome.alarms.create(WHITELIST_ALARM, { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === WHITELIST_ALARM) refreshIfProtected();
});
chrome.runtime.onStartup.addListener(refreshIfProtected);
chrome.runtime.onInstalled.addListener(refreshIfProtected);
