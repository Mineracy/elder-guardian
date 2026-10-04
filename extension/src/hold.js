const POLL_MS = 3000;
const params = new URLSearchParams(location.search);
const target = params.get('target') || '';
const trigger = params.get('trigger') || 'NON_WHITELISTED_DOMAIN';
const kind = params.get('kind') || 'navigate';
const storageKey = `interventionId:${target}`;

const $ = (id) => document.getElementById(id);
const send = (message) =>
  new Promise((resolve) => chrome.runtime.sendMessage(message, (res) => resolve(res ?? {})));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

$('target').textContent = target;
$('back').addEventListener('click', () => {
  // Blocked pages never loaded, so "back" would just re-trigger the hold; start fresh instead.
  chrome.tabs.update({ url: 'about:blank' });
});

function showEducation(message, warn) {
  $('education-text').textContent = message; // textContent: AI output is never parsed as HTML
  $('education-title').textContent = warn ? 'How to spot this next time' : 'While you wait';
  $('education').hidden = !message;
  $('education').classList.toggle('warn', warn);
}

function showError(message) {
  $('title').textContent = "We couldn't reach Guardian";
  $('subtitle').textContent = `${message}. For your safety this page stays blocked. Please reload in a moment or ask your trusted contact.`;
  $('spinner').hidden = true;
}

async function onAllowed() {
  $('icon').textContent = '✅';
  $('title').textContent = 'Approved';
  $('subtitle').textContent = 'Your trusted contact said this is okay. Taking you there now…';
  $('spinner').hidden = true;
  $('education').hidden = true;
  await send({ action: 'RELEASE', target });
  sessionStorage.removeItem(storageKey);
  if (kind === 'download') {
    chrome.downloads.download({ url: target });
    $('subtitle').textContent = 'Your download has started.';
  } else {
    location.replace(target);
  }
}

function onDenied(data) {
  $('icon').textContent = '🛑';
  $('title').textContent = 'This was blocked';
  $('subtitle').textContent =
    data.reason === 'no_trusted_contact'
      ? 'You have not added a trusted contact yet. Click the Guardian icon in your toolbar to add one.'
      : 'This was not approved. Here is what to look out for next time:';
  $('spinner').hidden = true;
  showEducation(data.userEducationMessage, true);
}

async function main() {
  let data;
  let id = sessionStorage.getItem(storageKey);
  if (id) {
    data = await send({ action: 'GET_INTERVENTION', id });
  } else {
    data = await send({
      action: 'CREATE_INTERVENTION',
      payload: { targetUrl: target, triggerType: trigger, context: params.get('context') || undefined },
    });
    if (data.id) sessionStorage.setItem(storageKey, data.id);
  }
  if (data.error) return showError(data.error);
  id = data.id;

  while (true) {
    if (data.status === 'allowed') return onAllowed();
    if (data.status === 'denied') return onDenied(data);
    showEducation(data.userEducationMessage, false);
    await sleep(POLL_MS);
    data = await send({ action: 'GET_INTERVENTION', id });
    if (data.error) return showError(data.error);
  }
}

main();
