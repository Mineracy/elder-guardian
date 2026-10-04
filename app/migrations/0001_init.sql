-- Anti-Scam Guardian schema (Cloudflare D1 / SQLite)

CREATE TABLE users (
  id            TEXT PRIMARY KEY,
  email         TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL, -- pbkdf2$<iterations>$<salt b64>$<hash b64>
  role          TEXT NOT NULL CHECK (role IN ('protected', 'trusted')),
  created_at    INTEGER NOT NULL
);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY, -- SHA-256 of the bearer token; the raw token is never stored
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);

CREATE TABLE contact_pairings (
  id                TEXT PRIMARY KEY,
  protected_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  trusted_email     TEXT NOT NULL,
  created_at        INTEGER NOT NULL,
  UNIQUE (protected_user_id, trusted_email)
);

CREATE TABLE whitelist_domains (
  id         TEXT PRIMARY KEY,
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  domain     TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  UNIQUE (user_id, domain)
);

CREATE TABLE intervention_requests (
  id                     TEXT PRIMARY KEY,
  user_id                TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_url             TEXT NOT NULL,
  domain                 TEXT NOT NULL,
  trigger_type           TEXT NOT NULL,
  context                TEXT,
  threat_level           TEXT NOT NULL,
  risk_summary           TEXT NOT NULL,
  user_education_message TEXT NOT NULL,
  trusted_contact_alert  TEXT NOT NULL,
  review_token           TEXT NOT NULL UNIQUE,
  status                 TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'allowed', 'denied')),
  used_fallback          INTEGER NOT NULL DEFAULT 0,
  created_at             INTEGER NOT NULL,
  expires_at             INTEGER NOT NULL,
  resolved_at            INTEGER
);

CREATE INDEX idx_interventions_user ON intervention_requests (user_id, created_at);
