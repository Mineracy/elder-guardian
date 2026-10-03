(function () {
  const bodyText = (document.body && document.body.innerText) ? document.body.innerText.toLowerCase() : '';

  const scamIndicators = [
    'call microsoft support',
    'computer has been locked',
    'toll-free helpline',
    'call apple support',
    'virus alert from microsoft'
  ];

  const matched = scamIndicators.find(phrase => bodyText.includes(phrase));

  if (matched) {
    chrome.runtime.sendMessage({
      action: 'THREAT_DETECTED',
      payload: {
        threatType: 'FAKE_TECH_SUPPORT_POPUP',
        url: window.location.href,
        phrase: matched
      }
    });
  }
})();
