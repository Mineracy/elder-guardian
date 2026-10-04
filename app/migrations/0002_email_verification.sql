-- Guardians must prove they own the email the protected person entered before they can approve anything.
ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;

CREATE TABLE email_verifications (
  token_hash TEXT PRIMARY KEY, -- SHA-256 of the emailed token
  user_id    TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL
);
