const ALERT_API_URL = 'http://localhost:3000/api/alerts';
const FORM_API_URL = 'http://localhost:3000/api/form';

async function postToHono(url, payload) {
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });

  if (!res.ok) {
    throw new Error(`Request failed with status ${res.status}`);
  }

  return await res.json();
}

async function dispatchAlert(payload) {
  try {
    const data = await postToHono(ALERT_API_URL, payload);
    console.log('[Background] Threat reported to Hono:', data);
    return data;
  } catch (err) {
    console.error('[Background] Failed to send alert to Hono:', err);
    return { error: err.message };
  }
}

async function sendFormToHono(payload) {
  try {
    const formBody = new URLSearchParams(payload).toString();
    const res = await fetch(FORM_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded;charset=UTF-8' },
      body: formBody
    });

    if (!res.ok) {
      throw new Error(`Request failed with status ${res.status}`);
    }

    const data = await res.json();
    console.log('[Background] Form sent to Hono:', data);
    return { ok: true, data };
  } catch (err) {
    console.error('[Background] Failed to send form to Hono:', err);
    return { ok: false, error: err.message };
  }
}

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.action === 'THREAT_DETECTED') {
    dispatchAlert(message.payload).then((result) => {
      sendResponse({ received: true, result });
    });
    return true;
  }

  if (message.action === 'SEND_TO_HONO') {
    sendFormToHono(message.payload).then((result) => {
      sendResponse(result);
    });
    return true;
  }

  return false;
});

if (chrome.downloads && chrome.downloads.onCreated) {
  chrome.downloads.onCreated.addListener((downloadItem) => {
    const dangerousPatterns = [/anydesk/i, /teamviewer/i, /rustdesk/i, /screenconnect/i];
    const fileName = downloadItem.filename || '';
    const match = dangerousPatterns.some((pattern) => pattern.test(fileName));

    if (match) {
      dispatchAlert({
        threatType: 'DANGEROUS_REMOTE_TOOL_DOWNLOAD',
        url: downloadItem.url,
        phrase: fileName
      });
    }
  });
}
