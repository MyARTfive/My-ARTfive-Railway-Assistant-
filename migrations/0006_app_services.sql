-- My ARTfive! App Management: owner-managed service catalogue.
-- Additive only; existing ticket, payment and customer records are untouched.
CREATE TABLE IF NOT EXISTS app_services (
  id TEXT PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  icon TEXT NOT NULL DEFAULT 'fa-solid fa-layer-group',
  display_order INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('active','inactive','draft')),
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_app_services_status_order
  ON app_services(status, display_order, created_at);
