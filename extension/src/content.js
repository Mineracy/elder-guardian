// Scans the page for the patterns scammers use. Runs on every page, including allowed sites.
(function () {
  const PAYMENT_THRESHOLD = 1000; // dollars; larger card payments are shown to the guardian first
  const MAX_TEXT = 200000;
  const RESCAN_DELAYS_MS = [3000, 8000]; // many scam popups are injected a moment after load

  const host = location.hostname;
  const isLocal = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(host) || host.endsWith('.local');

  const hasPassword = () => !!document.querySelector('input[type="password"]');
  const hasCardField = () =>
    !!document.querySelector(
      'input[autocomplete~="cc-number"], input[name*="cardnumber" i], input[id*="cardnumber" i], input[name*="card-number" i], input[name*="card_number" i]',
    );

  function largestDollarAmount(text) {
    let max = 0;
    for (const m of text.matchAll(/\$\s?(\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{2})?/g)) {
      max = Math.max(max, Number(m[1].replace(/,/g, '')));
    }
    return max;
  }

  // Ordered most to least serious; the first hit wins. Each gets the page's lower-cased text.
  const detectors = [
    (text) => {
      const phrase = [
        'call microsoft support', 'computer has been locked', 'toll-free helpline', 'call apple support',
        'virus alert from microsoft', 'your computer is infected', 'your pc has been locked',
        'windows defender security alert', 'do not restart your computer', 'call technical support',
      ].find((p) => text.includes(p));
      return phrase && { trigger: 'FAKE_TECH_SUPPORT_POPUP', phrase };
    },
    (text) => {
      const cards = (text.match(/gift ?cards?|itunes card|google play card|steam card|bitcoin atm|pay (?:with|in) (?:bitcoin|crypto)|wire (?:the )?money/) || [])[0];
      const asksToPay = /(pay|buy|purchase|send|read (?:me )?the (?:code|numbers)|scratch|pin)/.test(text);
      const pressure = /(urgent|immediately|irs|police|microsoft|apple|arrest|fine|bail|grandson|granddaughter|refund|fee)/.test(text);
      return cards && asksToPay && pressure && { trigger: 'GIFT_CARD_PAYMENT', phrase: cards };
    },
    (text) => {
      const phrase = (text.match(/social security (?:number )?(?:has been|is) (?:suspended|compromised|blocked)|arrest warrant|legal action (?:will be|has been) taken|warrant (?:has been )?issued|irs (?:lawsuit|notice of)|unpaid (?:taxes|fines?)/) || [])[0];
      return phrase && { trigger: 'GOV_IMPERSONATION_THREAT', phrase };
    },
    (text) => {
      const prize = (text.match(/you(?:'ve| have) won|claim your prize|you have been selected|lottery winner|unclaimed prize/) || [])[0];
      const wantsMoney = /(processing fee|shipping fee|claim now|enter your (?:card|details|address)|pay)/.test(text);
      return prize && wantsMoney && { trigger: 'PRIZE_OR_LOTTERY', phrase: prize };
    },
    (text) => {
      const phrase = (text.match(/verify your account|account (?:has been )?(?:suspended|locked|limited|restricted)|unusual (?:sign-?in|activity)|confirm your identity|your account will be (?:closed|suspended)|action required/) || [])[0];
      return phrase && hasPassword() && { trigger: 'ACCOUNT_VERIFICATION_PHISH', phrase };
    },
    () =>
      location.protocol === 'http:' && !isLocal && (hasPassword() || hasCardField())
        ? { trigger: 'INSECURE_LOGIN_FORM', phrase: 'password or card details requested on an unencrypted page' }
        : null,
    (text) => {
      if (!hasCardField()) return null;
      const amount = largestDollarAmount(text);
      return amount >= PAYMENT_THRESHOLD
        ? { trigger: 'LARGE_PAYMENT_FORM', phrase: `card payment form showing $${amount.toLocaleString('en-US')}` }
        : null;
    },
  ];

  let reported = false;
  function scan() {
    if (reported) return;
    const text = ((document.body && document.body.innerText) || '').toLowerCase().slice(0, MAX_TEXT);
    for (const detect of detectors) {
      const hit = detect(text);
      if (hit) {
        reported = true;
        chrome.runtime.sendMessage({ action: 'SCAM_CONTENT', ...hit });
        return;
      }
    }
  }

  scan();
  RESCAN_DELAYS_MS.forEach((ms) => setTimeout(scan, ms));
})();
