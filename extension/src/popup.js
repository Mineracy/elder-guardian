const form = document.getElementById('hono-form');
const responseBox = document.getElementById('response');

form.addEventListener('submit', (event) => {
  event.preventDefault();

  const formData = new FormData(form);
  const payload = Object.fromEntries(formData.entries());

  responseBox.textContent = 'Sending...';

  chrome.runtime.sendMessage(
    {
      action: 'SEND_TO_HONO',
      payload,
    },
    (response) => {
      if (chrome.runtime.lastError) {
        responseBox.textContent = `Error: ${chrome.runtime.lastError.message}`;
        return;
      }

      responseBox.textContent = JSON.stringify(response, null, 2);
    }
  );
});
