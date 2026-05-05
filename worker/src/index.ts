import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { authRoutes } from './auth'
import { projectRoutes } from './projects'

const app = new Hono<{ Bindings: { DB: D1Database; JWT_SECRET: string } }>()

app.use('*', cors({
  origin: [
    'https://buildquant-frontend.pages.dev',
    'https://b0acca90.buildquant-frontend.pages.dev',
    'http://localhost:3000',
    'http://127.0.0.1:5500',
  ],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}))

app.route('/auth', authRoutes)
app.route('/projects', projectRoutes)

app.get('/', (c) => c.json({ status: 'BuildQuant API v4 — Cloudflare Workers' }))

export default app
