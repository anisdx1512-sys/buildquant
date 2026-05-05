import { Hono } from 'hono'

type Env = { DB: D1Database; JWT_SECRET: string }
export const authRoutes = new Hono<{ Bindings: Env }>()

/* ── JWT helpers using Web Crypto API ── */
async function getKey(secret: string) {
  return crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  )
}

function b64url(buf: ArrayBuffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

function decodeB64url(s: string) {
  s = s.replace(/-/g, '+').replace(/_/g, '/')
  while (s.length % 4) s += '='
  return Uint8Array.from(atob(s), c => c.charCodeAt(0))
}

export async function signJWT(payload: object, secret: string): Promise<string> {
  const header = b64url(new TextEncoder().encode(JSON.stringify({ alg: 'HS256', typ: 'JWT' })))
  const body   = b64url(new TextEncoder().encode(JSON.stringify(payload)))
  const key    = await getKey(secret)
  const sig    = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${header}.${body}`))
  return `${header}.${body}.${b64url(sig)}`
}

export async function verifyJWT(token: string, secret: string): Promise<any> {
  const parts = token.split('.')
  if (parts.length !== 3) throw new Error('Invalid token')
  const key  = await getKey(secret)
  const ok   = await crypto.subtle.verify(
    'HMAC', key,
    decodeB64url(parts[2]),
    new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
  )
  if (!ok) throw new Error('Invalid signature')
  const payload = JSON.parse(new TextDecoder().decode(decodeB64url(parts[1])))
  if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) throw new Error('Token expired')
  return payload
}

/* ── Hash password ── */
async function hashPassword(pw: string): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256',
    new TextEncoder().encode(pw + 'BQ_SALT_2024'))
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('')
}

/* ── REGISTER ── */
authRoutes.post('/register', async (c) => {
  const { email, password, prenom } = await c.req.json()
  if (!email || !password || !prenom)
    return c.json({ error: 'Champs manquants' }, 400)
  if (password.length < 8)
    return c.json({ error: 'Mot de passe min. 8 caractères' }, 400)

  const exists = await c.env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first()
  if (exists) return c.json({ error: 'Email déjà utilisé' }, 409)

  const hashed = await hashPassword(password)
  const userId = crypto.randomUUID()

  await c.env.DB.prepare(
    'INSERT INTO users (id, email, password_hash, prenom, created_at) VALUES (?, ?, ?, ?, ?)'
  ).bind(userId, email, hashed, prenom, new Date().toISOString()).run()

  const token = await signJWT(
    { sub: userId, email, prenom, exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600 },
    c.env.JWT_SECRET
  )
  return c.json({ access_token: token, user: { id: userId, email, user_metadata: { prenom } } })
})

/* ── LOGIN ── */
authRoutes.post('/login', async (c) => {
  const { email, password } = await c.req.json()
  if (!email || !password) return c.json({ error: 'Champs manquants' }, 400)

  const hashed = await hashPassword(password)
  const user = await c.env.DB.prepare(
    'SELECT id, email, prenom FROM users WHERE email = ? AND password_hash = ?'
  ).bind(email, hashed).first<{ id: string; email: string; prenom: string }>()

  if (!user) return c.json({ error: 'Email ou mot de passe incorrect' }, 401)

  const token = await signJWT(
    { sub: user.id, email: user.email, prenom: user.prenom, exp: Math.floor(Date.now() / 1000) + 7 * 24 * 3600 },
    c.env.JWT_SECRET
  )
  return c.json({ access_token: token, user: { id: user.id, email: user.email, user_metadata: { prenom: user.prenom } } })
})

/* ── GET USER ── */
authRoutes.get('/user', async (c) => {
  const auth = c.req.header('Authorization')
  if (!auth) return c.json({ error: 'Non autorisé' }, 401)
  try {
    const payload = await verifyJWT(auth.replace('Bearer ', ''), c.env.JWT_SECRET)
    return c.json({ id: payload.sub, email: payload.email, user_metadata: { prenom: payload.prenom } })
  } catch {
    return c.json({ error: 'Token invalide' }, 401)
  }
})

/* ── LOGOUT ── */
authRoutes.post('/logout', (c) => c.json({ message: 'Déconnecté' }))
