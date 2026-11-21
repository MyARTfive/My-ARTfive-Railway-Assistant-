-- Secure Option 11 Manager credentials in D1. Existing app data is retained.
CREATE TABLE IF NOT EXISTS manager_credentials (
  owner_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  phone TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
