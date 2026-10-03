const API_URL = 'http://localhost:3000/api/alerts';

async function dispatchAlert(payload) {
  try {
    const res = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    const data = await res.json();
    console.log('[Background] Threat reported to Hono:', data);
  } catch (err) {
    console.error('[Background] Failed to send alert to Hono:', err);
  }
}

// 1. Listen for detections sent from content script
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.action === 'THREAT_DETECTED') {
    dispatchAlert(message.payload);
    sendResponse({ received: true });
  }
  return true;
});

// 2. Intercept remote-desktop software downloads (AnyDesk, TeamViewer, etc.)
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
