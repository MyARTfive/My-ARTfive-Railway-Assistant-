-- Option 10: owner-only visitor activity and Manager-gated control sessions.
-- Stores approximate Cloudflare location and technical visitor details, not exact addresses.
CREATE TABLE IF NOT EXISTS visitor_activity (
  visitor_key TEXT PRIMARY KEY,
  ip_address TEXT NOT NULL,
  visitor_name TEXT NOT NULL DEFAULT 'Unknown',
  city TEXT,
  region TEXT,
  country TEXT,
  device TEXT,
  operating_system TEXT,
  browser TEXT,
  isp TEXT,
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  visit_count INTEGER NOT NULL DEFAULT 1,
  last_path TEXT
);
CREATE INDEX IF NOT EXISTS idx_visitor_activity_last_seen ON visitor_activity(last_seen);
CREATE INDEX IF NOT EXISTS idx_visitor_activity_ip ON visitor_activity(ip_address);

CREATE TABLE IF NOT EXISTS manager_sessions (
  token_hash TEXT PRIMARY KEY,
  owner_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_manager_sessions_owner ON manager_sessions(owner_id);
CREATE INDEX IF NOT EXISTS idx_manager_sessions_expiry ON manager_sessions(expires_at);
