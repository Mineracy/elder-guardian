import { Hono } from 'hono'
import { cors } from 'hono/cors'

const app = new Hono()

app.use(
  '*',
  cors({
    origin: ['http://localhost:3000', 'chrome-extension://*'],
    allowMethods: ['GET', 'POST', 'OPTIONS'],
    allowHeaders: ['Content-Type'],
  }),
)

app.get('/', (c) => {
  return c.html(`
    <!DOCTYPE html>
    <html>
      <head>
        <meta charset="UTF-8" />
        <title>Hono Form Demo</title>
      </head>
      <body>
        <h1>Hono Form Demo</h1>
        <form method="POST" action="/api/form" enctype="multipart/form-data">
          <label>
            Name:
            <input type="text" name="name" value="Friend" />
          </label>
          <br /><br />
          <label>
            Message:
            <textarea name="message" rows="4" cols="40">Hello from the extension</textarea>
          </label>
          <br /><br />
          <button type="submit">Send to Hono</button>
        </form>
      </body>
    </html>
  `)
})

app.post('/api/form', async (c) => {
  const formData = await c.req.parseBody()
  const name = String(formData.name ?? 'Friend')
  const message = String(formData.message ?? 'No message provided')

  return c.json({
    ok: true,
    received: {
      name,
      message,
    },
    echo: `Hono says: hello ${name}! You sent "${message}".`,
  })
})

app.post('/api/alerts', async (c) => {
  const payload = await c.req.json().catch(() => ({}))

  return c.json({
    ok: true,
    message: 'Alert received by Hono',
    payload,
    echo: 'Hono has received your alert payload.',
  })
})

app.get('/health', (c) => {
  return c.json({ ok: true, service: 'hono-app' })
})

export default app
