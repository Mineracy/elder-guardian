// Watches for payments / transfers above the limit the guardian set and warns or holds them.
// Runs in every frame (a bank site may be embedded) and finds the amount from the page itself, so it
// doesn't depend on any one site's markup. Turn on logging with: chrome.storage.local.set({ debugTx: true })
(function () {
  const APPROVAL_MEMORY_MS = 15 * 60 * 1000; // an approved amount isn't asked about again for a while
  const POLL_MS = 3000;
  const BYPASS_MS = 2000;
  const TYPING_PAUSE_MS = 1200; // wait for the person to finish typing an amount before judging it

  const ACTION_WORDS = /\b(send|transfer|pay|payment|confirm|submit|deposit|withdraw|wire|zelle|venmo|purchase|buy|order|donate|complete|authorize|next|continue)\b/i;
  const AMOUNT_LABEL = /amount|\bsum\b|dollar|\$|how much|payment|\bpay\b|transfer|\bsend\b|total|value/;
  const NOT_AMOUNT_LABEL = /account|routing|card|cvv|cvc|zip|postal|phone|\bpin\b|ssn|social|date|year|month|check number|reference|memo|note|quantity|\bqty\b/;
  const PAYMENT_BUTTON = /\b(submit|pay|send|confirm|continue|transfer|deposit|withdraw|next)\b/i;
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

  async function syncPolicy() {
    try {
      const existing = await chrome.storage.local.get('policy');
      if (existing.policy?.transactionLimit) {
        policy = existing.policy;
        return;
      }
      const data = await new Promise((resolve) => {
        try {
          chrome.runtime.sendMessage({ action: 'GET_POLICY' }, (res) => resolve(res || {}));
        } catch {
          resolve({});
        }
      });
      if (data && data.transactionLimit) {
        const next = { ...data, backendHost: location.hostname || null };
        policy = next;
        await chrome.storage.local.set({ policy: next });
      }
    } catch (err) {
      log('syncPolicy failed', err);
    }
  }

  syncPolicy();

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

  const BUTTON_SELECTOR = 'button, input[type="submit"], input[type="button"], input[type="image"], [role="button"]';
  const nameOf = (button) => (button.innerText || button.value || button.getAttribute('aria-label') || '').trim();

  // After a denial, blank and disable the amount field(s) and the payment buttons next to them, and nothing else
  // on the page (history, navigation, other forms keep working). Reload the page to start over.
  function lockPaymentForm() {
    const amountInputs = [...document.querySelectorAll('input, textarea, [contenteditable="true"]')].filter((input) => {
      const type = (input.getAttribute('type') || 'text').toLowerCase();
      if (SKIP_TYPES.has(type) || input.disabled || input.readOnly) return false;
      return AMOUNT_LABEL.test(labelText(input));
    });

    const containers = new Set();
    for (const input of amountInputs) {
      input.value = '';
      input.setAttribute('aria-disabled', 'true');
      input.setAttribute('title', 'Payment blocked by Elder Guardian');
      input.readOnly = true;
      input.disabled = true;
      input.dispatchEvent(new Event('input', { bubbles: true }));

      // The nearest ancestor that also holds a payment button is this payment's form.
      let node = input.parentElement;
      for (let i = 0; node && i < 8; i++, node = node.parentElement) {
        if ([...node.querySelectorAll(BUTTON_SELECTOR)].some((b) => PAYMENT_BUTTON.test(nameOf(b)))) { containers.add(node); break; }
      }
    }

    for (const container of containers) {
      for (const button of container.querySelectorAll(BUTTON_SELECTOR)) {
        if (!PAYMENT_BUTTON.test(nameOf(button))) continue;
        button.disabled = true;
        button.setAttribute('aria-disabled', 'true');
        button.style.pointerEvents = 'none';
        button.style.opacity = '0.5';
      }
    }
  }

  // Empties a field the way a person would, so frameworks that track the value (React and friends) notice too.
  function clearField(field) {
    try {
      const proto = field instanceof HTMLTextAreaElement ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      const setter = Object.getOwnPropertyDescriptor(proto, 'value');
      if (setter && setter.set && 'value' in field) setter.set.call(field, '');
      else field.textContent = '';
      field.dispatchEvent(new Event('input', { bubbles: true }));
    } catch (err) { log('could not clear the field', err); }
  }

  function fmt(n) { return n.toLocaleString('en-US', { style: 'currency', currency: 'USD' }); }

  // Is this amount over the limit and not yet approved?
  function needsApproval(amount) {
    if (!policy || !policy.transactionLimit || !amount || amount <= policy.transactionLimit.amount) return false;
    return (approved[approvalKey(Math.round(amount * 100))] || 0) <= Date.now();
  }

  // Releases a held click/submit. The page isn't frozen while the overlay is up, so the amount may have been
  // changed since it was approved: check again and hold the new amount instead of sending it unapproved.
  function resume(kind, el, submitter) {
    const amount = findAmount(submitter || el);
    if (needsApproval(amount)) {
      log('amount changed while waiting', amount);
      const { amount: limit, action } = policy.transactionLimit;
      showOverlay({ amount, limit, action, cents: Math.round(amount * 100), label: labelOf(submitter || el), proceed: () => resume(kind, el, submitter) });
      return;
    }
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

  // An amount typed into a payment field is judged once the person pauses (or leaves the field), never per
  // keystroke: "1200" passes through "120" on the way, and only the final amount should reach the guardian.
  // The events themselves are left alone so the page's own state keeps up with the field.
  let typedTimer = null;
  function onTypedAmount(e, immediate) {
    const target = e.target;
    if (!paymentFieldAmount(target)) return; // other fields don't affect a pending check of the amount field
    clearTimeout(typedTimer);
    typedTimer = setTimeout(() => holdTypedAmount(target), immediate ? 0 : TYPING_PAUSE_MS);
  }

  function holdTypedAmount(target) {
    if (!policy || !policy.transactionLimit || Date.now() < bypassUntil || overlay || !target.isConnected) return;
    const amount = paymentFieldAmount(target); // read again: it may have changed or been cleared meanwhile
    if (!needsApproval(amount)) return;
    const { amount: limit, action } = policy.transactionLimit;
    showOverlay({
      amount, limit, action, cents: Math.round(amount * 100), label: labelOf(target),
      proceed: () => { if (target.focus) target.focus(); },
      onCancel: () => clearField(target), // cancelling the payment also empties the amount, so it isn't re-judged
    });
  }

  document.addEventListener('click', (e) => { intercept(e, 'click'); }, true);
  document.addEventListener('submit', (e) => { intercept(e, 'submit'); }, true);
  document.addEventListener('input', (e) => { onTypedAmount(e, false); }, true);
  document.addEventListener('change', (e) => { onTypedAmount(e, true); }, true);

  const send = (message) => new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(message, (res) => {
        const failed = chrome.runtime.lastError; // read it so Chrome doesn't log "unchecked lastError"
        resolve(res || { error: failed ? 'Elder Guardian was just updated. Reload this page' : 'No response' });
      });
    } catch {
      resolve({ error: 'Elder Guardian was just updated. Reload this page' });
    }
  });

  function showOverlay({ amount, limit, action, cents, label, proceed, onCancel }) {
    const host = document.createElement('div');
    const root = host.attachShadow({ mode: debug ? 'open' : 'closed' });
    const style = document.createElement('style');
    style.textContent = `
      img{display:block;margin:0 auto 4px}
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
    const cancelPayment = () => { close(); if (onCancel) onCancel(); };
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
      row.append(button('Cancel the payment', cancelPayment), button("I'm sure, continue", approve, true));
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
    const cancel = button('Cancel the payment', cancelPayment, true);
    row.append(cancel);
    const logo = document.createElement('img');
    logo.src = chrome.runtime.getURL('icons/icon-128.png');
    logo.alt = 'Elder Guardian';
    logo.width = logo.height = 64;
    logo.addEventListener('error', () => logo.replaceWith(el('div', '🛡️', ''))); // e.g. a page that blocks extension images
    show(logo, title, note, spin, edu, row);

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
          lockPaymentForm();
          const denyClose = () => { lockPaymentForm(); close(); };
          cancel.onclick = denyClose;
          cancel.textContent = 'Close';
          title.textContent = 'This payment was not approved';
          note.textContent = data.reason === 'no_trusted_contact' ? 'You have not added a trusted contact yet, so large payments are paused.' : 'It has not been sent, and this payment form is now locked (reload the page to start a new one). Here is what to look out for next time:';
          spin.hidden = true;
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
