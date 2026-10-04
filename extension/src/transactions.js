// Watches for payments / transfers above the limit the guardian set and warns or holds them.
// Runs in every frame (a bank site may be embedded) and finds the amount from the page itself, so it
// doesn't depend on any one site's markup. Turn on logging with: chrome.storage.local.set({ debugTx: true })
(function () {
  const APPROVAL_MEMORY_MS = 15 * 60 * 1000; // an approved amount isn't asked about again for a while
  const POLL_MS = 3000;
  const BYPASS_MS = 2000;

  const ACTION_WORDS = /\b(send|transfer|pay|payment|confirm|submit|deposit|withdraw|wire|zelle|venmo|purchase|buy|order|donate|complete|authorize|next|continue)\b/i;
  const AMOUNT_LABEL = /amount|\bsum\b|dollar|\$|how much|payment|\bpay\b|transfer|\bsend\b|total|value/;
  const NOT_AMOUNT_LABEL = /account|routing|card|cvv|cvc|zip|postal|phone|\bpin\b|ssn|social|date|year|month|check number|reference|memo|note|quantity|\bqty\b/;
  const SKIP_TYPES = new Set(['hidden', 'password', 'checkbox', 'radio', 'file', 'submit', 'button', 'image', 'reset', 'email', 'date', 'time', 'tel', 'url', 'color', 'range']);

  let policy = null;
  let debug = false;
  let bypassUntil = 0;
  let overlay = null; // { host, close }
  let approved = {}; // `${host}:${cents}` -> expiry; kept in storage so reloads and multi-step flows aren't re-asked
  const approvalKey = (cents) => `${location.hostname}:${cents}`;

  const log = (...a) => { if (debug) console.log('[guardian:tx]', ...a); };

  chrome.storage.local.get(['policy', 'debugTx', 'txApproved']).then((v) => { policy = v.policy || null; debug = !!v.debugTx; approved = v.txApproved || {}; }).catch(() => {});
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== 'local') return;
    if (changes.policy) policy = changes.policy.newValue || null;
    if (changes.debugTx) debug = !!changes.debugTx.newValue;
    if (changes.txApproved) approved = changes.txApproved.newValue || {};
  });

  function parseMoney(raw) {
    if (raw == null) return null;
    const t = String(raw).trim().replace(/^(?:usd|us\$|\$)\s*/i, '').replace(/\s*(?:usd|dollars?)$/i, '');
    if (!/^(?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{1,2})?$/.test(t)) return null;
    const n = Number(t.replace(/,/g, ''));
    return Number.isFinite(n) && n > 0 ? n : null;
  }

  function labelText(input) {
    const parts = [input.name, input.id, input.placeholder, input.getAttribute('aria-label'), input.title];
    if (input.labels) for (const l of input.labels) parts.push(l.innerText);
    const by = input.getAttribute('aria-labelledby');
    if (by) by.split(/\s+/).forEach((id) => { const el = document.getElementById(id); if (el) parts.push(el.innerText); });
    if (input.previousElementSibling) parts.push(input.previousElementSibling.innerText || '');
    // The parent's text only describes this input when it is the parent's only field; otherwise it also
    // contains the neighbouring fields' labels (e.g. "To account" next to "Transfer amount").
    const parent = input.parentElement;
    if (parent && parent.querySelectorAll('input, textarea, select, [contenteditable="true"]').length === 1) {
      parts.push((parent.innerText || '').slice(0, 80));
    }
    return parts.filter(Boolean).join(' ').toLowerCase();
  }

  // Largest dollar amount typed into an amount-looking field inside `scope`.
  function amountInFields(scope) {
    let labelled = 0;
    let loose = 0;
    for (const input of scope.querySelectorAll('input, textarea, [contenteditable="true"]')) {
      const type = (input.getAttribute('type') || 'text').toLowerCase();
      if (SKIP_TYPES.has(type) || input.disabled) continue;
      const value = parseMoney(input.value !== undefined ? input.value : input.textContent);
      if (value === null) continue;
      const label = labelText(input);
      if (AMOUNT_LABEL.test(label) && !(NOT_AMOUNT_LABEL.test(label) && !/amount/.test(label))) labelled = Math.max(labelled, value);
      else if (!NOT_AMOUNT_LABEL.test(label) && (type === 'number' || /decimal|numeric/.test(input.getAttribute('inputmode') || '') || /^\s*\$/.test(input.value || ''))) loose = Math.max(loose, value);
    }
    return labelled || loose || 0;
  }

  // Confirmation dialogs often state the amount in text: "Send $1,200.00 to Sam?"
  function amountInDialog(el) {
    const dialog = el.closest('[role="dialog"], [aria-modal="true"], dialog, .modal');
    if (!dialog) return 0;
    const text = (dialog.innerText || '').slice(0, 2000);
    const near = text.match(/(?:send(?:ing)?|transfer(?:ring)?|pay(?:ing)?|withdraw(?:ing)?|deposit(?:ing)?|amount|total)[^$\d\n]{0,40}\$\s?((?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{1,2})?)/i);
    if (near) return parseMoney(near[1]) || 0;
    const all = [...new Set([...text.matchAll(/\$\s?((?:\d{1,3}(?:,\d{3})+|\d+)(?:\.\d{1,2})?)/g)].map((m) => m[1]))];
    return all.length === 1 ? parseMoney(all[0]) || 0 : 0;
  }

  function findAmount(el) {
    let node = el;
    for (let i = 0; node && node !== document.documentElement && i < 8; i++, node = node.parentElement) {
      const found = amountInFields(node);
      if (found) return found;
    }
    return amountInDialog(el);
  }

  function paymentFieldAmount(target) {
    if (!target || !(target instanceof HTMLElement)) return 0;
    const type = (target.getAttribute('type') || 'text').toLowerCase();
    if (SKIP_TYPES.has(type) || target.disabled || target.readOnly) return 0;
    const value = parseMoney(target.value !== undefined ? target.value : target.textContent);
    if (value === null) return 0;
    const label = labelText(target);
    const looksLikePaymentField = /amount|\bsum\b|dollar|\$|how much|payment|\bpay\b|transfer|\bsend\b|total|value/.test(label) || /enter amount/.test(label);
    const badLabel = /account|routing|card|cvv|cvc|zip|postal|phone|\bpin\b|ssn|social|date|year|month|check number|reference|memo|note|quantity|\bqty\b/.test(label);
    if (!looksLikePaymentField || (badLabel && !/amount/.test(label))) return 0;
    return value;
  }

  const actionable = (target) => target && target.closest && target.closest('button, input[type="submit"], input[type="button"], input[type="image"], [role="button"], a');
  const labelOf = (el) => (el.innerText || el.value || el.getAttribute('aria-label') || el.title || '').trim();
  const fromOverlay = (e) => overlay && e.composedPath().includes(overlay.host);

  function fmt(n) { return n.toLocaleString('en-US', { style: 'currency', currency: 'USD' }); }

  function resume(kind, el, submitter) {
    bypassUntil = Date.now() + BYPASS_MS;
    try {
      if (kind === 'submit' && el.requestSubmit) el.requestSubmit(submitter || undefined);
      else if (el && el.click) el.click();
    } catch (err) { log('resume failed', err); }
  }

  // Returns true when the event was a limit-exceeding transaction and has been stopped.
  function intercept(e, kind) {
    if (!policy || !policy.transactionLimit) return false;
    if (policy.backendHost && location.hostname === policy.backendHost) return false;
    if (Date.now() < bypassUntil || fromOverlay(e)) return false;

    let el;
    let submitter = null;
    if (kind === 'click') {
      el = actionable(e.target);
      if (!el || !ACTION_WORDS.test(labelOf(el))) return false;
    } else {
      el = e.target;
      submitter = e.submitter || null;
    }

    if (overlay) { e.preventDefault(); e.stopImmediatePropagation(); return true; } // one decision at a time

    const amount = findAmount(submitter || el);
    const { amount: limit, action } = policy.transactionLimit;
    log(kind, labelOf(el) || el.tagName, 'amount', amount, 'limit', limit);
    if (!amount || amount <= limit) return false;
    const cents = Math.round(amount * 100);
    if ((approved[approvalKey(cents)] || 0) > Date.now()) return false;

    e.preventDefault();
    e.stopImmediatePropagation();
    showOverlay({ amount, limit, action, cents, label: labelOf(submitter || el), proceed: () => resume(kind, el, submitter) });
    return true;
  }

  function interceptLargeTypedAmount(e) {
    if (!policy || !policy.transactionLimit) return false;
    if (Date.now() < bypassUntil || overlay) return false;

    const target = e.target;
    const amount = paymentFieldAmount(target);
    if (!amount) return false;

    const { amount: limit, action } = policy.transactionLimit;
    if (amount <= limit) return false;

    const cents = Math.round(amount * 100);
    if ((approved[approvalKey(cents)] || 0) > Date.now()) return false;

    e.preventDefault();
    e.stopImmediatePropagation();
    showOverlay({ amount, limit, action, cents, label: labelOf(target), proceed: () => {
      if (target && target.focus) target.focus();
    } });
    return true;
  }

  document.addEventListener('click', (e) => { intercept(e, 'click'); }, true);
  document.addEventListener('submit', (e) => { intercept(e, 'submit'); }, true);
  document.addEventListener('input', (e) => { interceptLargeTypedAmount(e); }, true);
  document.addEventListener('change', (e) => { interceptLargeTypedAmount(e); }, true);

  const send = (message) => new Promise((resolve) => chrome.runtime.sendMessage(message, (res) => resolve(res || { error: 'No response' })));

  function showOverlay({ amount, limit, action, cents, label, proceed }) {
    const host = document.createElement('div');
    const root = host.attachShadow({ mode: debug ? 'open' : 'closed' });
    const style = document.createElement('style');
    style.textContent = `
      .bg{position:fixed;inset:0;z-index:2147483647;background:rgba(15,23,42,.72);display:flex;align-items:center;justify-content:center;font-family:system-ui,sans-serif}
      .card{background:#fff;color:#1f2937;max-width:480px;margin:16px;padding:28px;border-radius:18px;text-align:center;box-shadow:0 10px 40px #0006}
      h1{margin:6px 0 10px;font-size:24px} p{font-size:17px;line-height:1.5;margin:8px 0}
      .edu{text-align:left;background:#f0fdf4;border-left:6px solid #16a34a;padding:2px 16px;border-radius:10px}
      .edu.warn{background:#fef2f2;border-color:#dc2626}
      .row{display:flex;gap:12px;justify-content:center;flex-wrap:wrap;margin-top:16px}
      button{font:inherit;font-size:17px;font-weight:600;padding:12px 20px;border:0;border-radius:12px;cursor:pointer;background:#4f46e5;color:#fff}
      button.secondary{background:#e5e7eb;color:#111827}
      .spin{width:32px;height:32px;margin:12px auto;border:4px solid #c7d2fe;border-top-color:#4f46e5;border-radius:50%;animation:s 1s linear infinite}
      @keyframes s{to{transform:rotate(360deg)}}`;
    const bg = document.createElement('div'); bg.className = 'bg';
    const card = document.createElement('div'); card.className = 'card';
    bg.append(card); root.append(style, bg);

    let closed = false;
    const close = () => { closed = true; host.remove(); overlay = null; };
    overlay = { host, close };
    document.documentElement.append(host);

    const el = (tag, text, cls) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = text; if (cls) n.className = cls; return n; };
    const button = (text, onClick, secondary) => { const b = el('button', text, secondary ? 'secondary' : ''); b.addEventListener('click', onClick); return b; };
    const show = (...nodes) => card.replaceChildren(...nodes);
    const approve = () => {
      const now = Date.now();
      approved = Object.fromEntries(Object.entries(approved).filter(([, expiry]) => expiry > now));
      approved[approvalKey(cents)] = now + APPROVAL_MEMORY_MS;
      chrome.storage.local.set({ txApproved: approved }).catch(() => {});
      close();
      proceed();
    };

    const over = `${fmt(amount)} is more than the ${fmt(limit)} limit set by your trusted contact.`;

    if (action === 'warn') {
      const row = el('div', '', 'row');
      row.append(button('Cancel the payment', close), button("I'm sure, continue", approve, true));
      show(
        el('div', '⚠️', ''), el('h1', 'Please double-check this payment'), el('p', over),
        el('p', 'Scammers often rush people into sending money. Only go ahead if you are sure who this is for and why.'),
        row,
      );
      return;
    }

    const title = el('h1', 'Awaiting verification');
    const note = el('p', `${over} We've asked them to approve it.`);
    const spin = el('div', '', 'spin');
    const edu = el('div', '', 'edu'); edu.hidden = true;
    const eduTitle = el('p', ''); eduTitle.style.fontWeight = '700'; const eduText = el('p', '');
    edu.append(eduTitle, eduText);
    const row = el('div', '', 'row');
    const cancel = button('Cancel the payment', close, true);
    row.append(cancel);
    show(el('div', '🛡️', ''), title, note, spin, edu, row);

    const fail = (message) => { title.textContent = "We couldn't reach Elder Guardian"; note.textContent = `${message}. For your safety this payment has not been sent.`; spin.hidden = true; cancel.textContent = 'Close'; };
    const showEdu = (text, warn, heading) => { eduTitle.textContent = heading; eduText.textContent = text; edu.className = warn ? 'edu warn' : 'edu'; edu.hidden = !text; };

    (async () => {
      const payload = { targetUrl: location.origin + location.pathname, triggerType: 'LARGE_TRANSACTION', amount, context: `Transaction of ${fmt(amount)} on ${location.hostname} (button: "${label.slice(0, 60)}")` };
      let data = await send({ action: 'CREATE_INTERVENTION', payload });
      while (!closed) {
        if (data.error) return fail(data.error);
        if (data.status === 'allowed') {
          title.textContent = 'Approved'; note.textContent = 'Your trusted contact said this is okay. Continuing…'; spin.hidden = true; edu.hidden = true;
          await new Promise((r) => setTimeout(r, 800));
          return closed ? undefined : approve();
        }
        if (data.status === 'denied') {
          title.textContent = 'This payment was not approved';
          note.textContent = data.reason === 'no_trusted_contact' ? 'You have not added a trusted contact yet, so large payments are paused.' : 'It has not been sent. Here is what to look out for next time:';
          spin.hidden = true; cancel.textContent = 'Close';
          return showEdu(data.userEducationMessage, true, 'How to spot this next time');
        }
        showEdu(data.userEducationMessage, false, 'While you wait');
        await new Promise((r) => setTimeout(r, POLL_MS));
        if (closed) return;
        data = await send({ action: 'GET_INTERVENTION', id: data.id });
      }
    })();
  }
})();
