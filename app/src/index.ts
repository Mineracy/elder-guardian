import { Hono } from 'hono'
import { cors } from 'hono/cors'
import auth from './routes/auth'
import interventions from './routes/interventions'
import review from './routes/review'
import settings from './routes/settings'
import type { AppEnv } from './types'

const app = new Hono<AppEnv>()

app.use(
  '/api/*',
  cors({
    origin: (origin) =>
      origin.startsWith('chrome-extension://') || origin.startsWith('http://localhost')
        ? origin
        : null,
    allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
  }),
)

app.route('/api/auth', auth)
app.route('/api', settings)
app.route('/api/interventions', interventions)
app.route('/review', review)

app.get('/health', (c) => c.json({ ok: true, service: 'guardian-backend' }))

export default app
