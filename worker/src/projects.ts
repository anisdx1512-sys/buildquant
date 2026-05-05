import { Hono } from 'hono'
import { verifyJWT } from './auth'

type Env = { DB: D1Database; JWT_SECRET: string }
const app = new Hono<{ Bindings: Env }>()

// Middleware auth
app.use('*', async (c, next) => {
  if (c.req.method === 'OPTIONS') return await next()
  const auth = c.req.header('Authorization')
  if (!auth) return c.json({ error: 'Non autorisé' }, 401)
  try {
    const payload = await verifyJWT(auth.replace('Bearer ', ''), c.env.JWT_SECRET)
    c.set('userId', payload.sub as string)
    await next()
  } catch {
    return c.json({ error: 'Token invalide' }, 401)
  }
})

// GET
app.get('/', async (c) => {
  const userId = c.get('userId')
  const { results } = await c.env.DB.prepare(
    'SELECT * FROM projects WHERE user_id = ? ORDER BY updated_at DESC'
  ).bind(userId).all()
  const projects = results.map((r: any) => JSON.parse(r.data))
  return c.json(projects)
})

// POST
app.post('/', async (c) => {
  const userId = c.get('userId')
  const data = await c.req.json()
  const id = data.id || Date.now()
  await c.env.DB.prepare(
    'INSERT OR REPLACE INTO projects (id, user_id, nom, data, updated_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(String(id), userId, data.nom, JSON.stringify(data), new Date().toISOString()).run()
  return c.json({ ok: true })
})

// DELETE
app.delete('/:id', async (c) => {
  const userId = c.get('userId')
  const id = c.req.param('id')
  await c.env.DB.prepare(
    'DELETE FROM projects WHERE id = ? AND user_id = ?'
  ).bind(id, userId).run()
  return c.json({ ok: true })
})

export { app as projectRoutes }
