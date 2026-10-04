(function () {
  const bodyText = document.body ? document.body.innerText.toLowerCase() : '';

  const scamIndicators = [
    'call microsoft support',
    'computer has been locked',
    'toll-free helpline',
    'call apple support',
    'virus alert from microsoft',
    'your computer is infected',
  ];

  const matched = scamIndicators.find((phrase) => bodyText.includes(phrase));
  if (matched) {
    chrome.runtime.sendMessage({ action: 'SCAM_CONTENT', phrase: matched });
  }
})();
