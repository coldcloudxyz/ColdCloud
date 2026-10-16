-- Add secure email verification for password-based accounts.
-- Existing accounts remain usable; only new registrations must verify.
ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN verification_token_hash TEXT;
ALTER TABLE users ADD COLUMN verification_expires_at TEXT;
UPDATE users SET email_verified = 1;
