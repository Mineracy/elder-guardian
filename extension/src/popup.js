import { apiFetch, authenticate, getSession, refreshWhitelist, signOut } from './api.js';

const $ = (id) => document.getElementById(id);
let mode = 'signin';

function showError(message) {
  $('error').textContent = message || '';
  $('error').hidden = !message;
}

function setMode(next) {
  mode = next;
  $('auth-submit').textContent = mode === 'signin' ? 'Sign in' : 'Create account';
  $('auth-toggle').textContent =
    mode === 'signin' ? 'New here? Create an account' : 'Already have an account? Sign in';
  $('role-row').hidden = mode === 'signin';
}

async function renderAccount(session) {
  $('who').textContent = `${session.email} (${session.role === 'protected' ? 'protected' : 'trusted contact'})`;
  const isProtected = session.role === 'protected';
  $('protected-only').hidden = !isProtected;
  $('trusted-only').hidden = isProtected;
  if (!isProtected) return;

  const [{ contacts }, domains] = await Promise.all([apiFetch('/api/contacts'), refreshWhitelist()]);
  const has = contacts.length > 0;
  $('contact-current').hidden = !has;
  $('contact-current').textContent = has ? `Approvals go to ${contacts[0].trusted_email}` : '';
  $('contact-form').hidden = has;
  $('contact-note').hidden = !has;
  $('whitelist').replaceChildren(
    ...domains.map((d) => Object.assign(document.createElement('li'), { textContent: d.domain })),
  );
}

async function render() {
  showError('');
  const session = await getSession();
  $('auth-form').hidden = !!session;
  $('account').hidden = !session;
  if (!session) return;
  try {
    await renderAccount(session);
  } catch (err) {
    showError(err.message);
    if (!(await getSession())) render(); // session expired
  }
}

$('auth-toggle').addEventListener('click', () => setMode(mode === 'signin' ? 'signup' : 'signin'));

$('auth-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    await authenticate(mode, f.get('email'), f.get('password'), mode === 'signup' ? f.get('role') : undefined);
    e.target.reset();
    await render();
  } catch (err) {
    showError(err.message);
  }
});

$('contact-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  try {
    await apiFetch('/api/contacts', { method: 'POST', body: { email: new FormData(e.target).get('email') } });
    await render();
  } catch (err) {
    showError(err.message);
  }
});

$('signout').addEventListener('click', async () => {
  await signOut();
  await render();
});

setMode('signin');
render();
