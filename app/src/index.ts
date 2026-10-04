import { Hono } from 'hono'
import { cors } from 'hono/cors'
import auth, { verify } from './routes/auth'
import guardian from './routes/guardian'
import interventions from './routes/interventions'
import review from './routes/review'
import settings from './routes/settings'
import type { AppEnv } from './types'

const app = new Hono<AppEnv>()

app.use(
  '/api/*',
  cors({
    origin: (origin, c) =>
      origin.startsWith('chrome-extension://') ||
      origin.startsWith('http://localhost') ||
      origin === c.env.WEB_URL
        ? origin
        : null,
    allowMethods: ['GET', 'POST', 'DELETE', 'OPTIONS'],
    allowHeaders: ['Content-Type', 'Authorization'],
  }),
)

app.route('/api/auth', auth)
app.route('/api/guardian', guardian)
app.route('/api', settings)
app.route('/api/interventions', interventions)
app.route('/review', review)
app.route('/verify', verify)

app.get('/health', (c) => c.json({ ok: true, service: 'guardian-backend' }))

export default app
