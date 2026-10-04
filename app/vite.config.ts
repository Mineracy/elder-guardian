import { cloudflare } from '@cloudflare/vite-plugin'
import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// One process: Vite serves the React app and runs the Hono Worker (with local D1) alongside it.
export default defineConfig({
  plugins: [react(), cloudflare()],
  server: { port: 3000 },
})
