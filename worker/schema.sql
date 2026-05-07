CREATE TABLE IF NOT EXISTS users (
  id           TEXT PRIMARY KEY,
  email        TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  prenom       TEXT,
  created_at   TEXT
);

CREATE TABLE IF NOT EXISTS projects (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  nom        TEXT,
  data       TEXT,  -- JSON complet du projet
  updated_at TEXT,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_projects_user ON projects(user_id);

CREATE TABLE IF NOT EXISTS reset_tokens (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL,
  code       TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  used       INTEGER DEFAULT 0,
  FOREIGN KEY (user_id) REFERENCES users(id)
);