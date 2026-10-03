import { Hono } from 'hono';
import { serve } from '@hono/node-server';
import { cors } from 'hono/cors';

const app = new Hono();

// Enable CORS for extension requests
app.use('/api/*', cors());

// Temporary memory store for threats
const alerts: Array<{ threatType: string; url: string; phrase?: string; timestamp: number }> = [];

// Caregiver Dashboard (Server-rendered HTML with Tailwind)
app.get('/', (c) => {
  return c.html(
    <html lang="en">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>Elder Guardian Dashboard</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <meta http-equiv="refresh" content="5" />
      </head>
      <body class="bg-slate-100 min-h-screen p-8 font-sans">
        <div class="max-w-2xl mx-auto bg-white p-6 rounded-2xl shadow-sm border border-slate-200">
          <div class="flex items-center justify-between pb-4 border-b border-slate-100 mb-6">
            <div>
              <h1 class="text-2xl font-bold text-slate-800">Elder Guardian Live Feed</h1>
              <p class="text-xs text-slate-400 mt-1">Auto-refreshes every 5 seconds</p>
            </div>
            <span class="inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800">
              System Active
            </span>
          </div>

          <div class="space-y-3">
            {alerts.length === 0 ? (
              <div class="text-center py-12 text-slate-400">
                <p class="text-sm">No threats detected yet.</p>
                <p class="text-xs mt-1">Extension is actively monitoring elder web sessions.</p>
              </div>
            ) : (
              alerts.map((a) => (
                <div class="p-4 border-l-4 border-rose-500 bg-rose-50/70 rounded-r-xl">
                  <div class="flex justify-between items-start">
                    <span class="font-bold text-sm text-rose-800 tracking-wide uppercase">{a.threatType}</span>
                    <span class="text-xs text-slate-400">{new Date(a.timestamp).toLocaleTimeString()}</span>
                  </div>
                  {a.phrase && (
                    <p class="text-xs text-rose-600 mt-1">
                      Matched keyword: <code>"{a.phrase}"</code>
                    </p>
                  )}
                  <p class="text-xs font-mono text-slate-500 mt-2 truncate bg-white/70 p-1.5 rounded border border-rose-100">
                    {a.url}
                  </p>
                </div>
              ))
            )}
          </div>
        </div>
      </body>
    </html>
  );
});

// Extension Telemetry API
app.get('/api/alerts', (c) => c.json({ alerts }));

app.post('/api/alerts', async (c) => {
  const body = await c.req.json();
  const alert = {
    threatType: body.threatType || 'GENERIC_SUSPICIOUS_ACTIVITY',
    url: body.url || 'Unknown URL',
    phrase: body.phrase || undefined,
    timestamp: Date.now(),
  };

  alerts.unshift(alert);
  console.log(`[THREAT FLAGGED] ${alert.threatType} on${alert.url}`);

  return c.json({ success: true, count: alerts.length }, 201);
});

const PORT = 3000;
serve({ fetch: app.fetch, port: PORT }, () => {
  console.log(`Hono backend running at http://localhost:${PORT}`);
});
