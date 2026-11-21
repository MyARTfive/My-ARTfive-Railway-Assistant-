-- My ARTfive! Railway Assistant: complete runtime schema for a fresh database.
-- Additive schema only. No Preview/customer data is copied or inserted.
-- Apply after migrations 0001 through 0006.

CREATE TABLE IF NOT EXISTS customer_engagement (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('subscribe', 'rating')),
  rating INTEGER,
  created_at INTEGER NOT NULL,
  UNIQUE (customer_id, device_id, action)
);

CREATE TABLE IF NOT EXISTS app_installations (
  installation_id TEXT PRIMARY KEY,
  first_seen INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS apk_downloads (
  id TEXT PRIMARY KEY,
  downloaded_at INTEGER NOT NULL,
  country TEXT,
  user_agent TEXT
);

CREATE TABLE IF NOT EXISTS apk_download_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  download_url TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS staff_notifications (
  id TEXT PRIMARY KEY,
  staff_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL,
  message TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'general',
  created_at INTEGER NOT NULL,
  read_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_staff_notifications_staff_created
  ON staff_notifications(staff_id, created_at DESC);

CREATE TABLE IF NOT EXISTS staff_chat_messages (
  id TEXT PRIMARY KEY,
  staff_id TEXT,
  sender_id TEXT NOT NULL REFERENCES users(id),
  sender_role TEXT NOT NULL CHECK (sender_role IN ('owner','staff')),
  sender_name TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_staff_chat_messages_staff_created
  ON staff_chat_messages(staff_id, created_at);

CREATE TABLE IF NOT EXISTS customer_enquiry_messages (
  id TEXT PRIMARY KEY,
  request_id TEXT,
  customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_id TEXT NOT NULL REFERENCES users(id),
  sender_role TEXT NOT NULL CHECK (sender_role IN ('owner','staff','customer')),
  sender_name TEXT NOT NULL,
  message TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_customer_enquiry_request
  ON customer_enquiry_messages(request_id);

CREATE TABLE IF NOT EXISTS customer_notifications (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  sender_id TEXT NOT NULL REFERENCES users(id),
  message TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  read_at INTEGER,
  ticket_id TEXT,
  target_option INTEGER,
  expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS customer_chat_settings (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  enabled INTEGER NOT NULL DEFAULT 1,
  updated_by TEXT,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS app_settings (
  setting_key TEXT PRIMARY KEY,
  setting_json TEXT NOT NULL,
  updated_by TEXT,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS app_updates (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  description TEXT NOT NULL,
  created_by TEXT NOT NULL REFERENCES users(id),
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS customer_payment_instructions (
  id TEXT PRIMARY KEY,
  request_id TEXT NOT NULL,
  customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  option_no INTEGER NOT NULL CHECK (option_no IN (2, 3)),
  amount_paise INTEGER NOT NULL CHECK (amount_paise > 0),
  message TEXT NOT NULL,
  updated_by TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  payment_status TEXT NOT NULL DEFAULT 'pending',
  verified_by TEXT,
  verified_at INTEGER,
  is_active INTEGER NOT NULL DEFAULT 1,
  UNIQUE (request_id, option_no)
);
CREATE INDEX IF NOT EXISTS idx_customer_payment_instructions_customer
  ON customer_payment_instructions(customer_id, option_no, updated_at DESC);

CREATE TABLE IF NOT EXISTS manager_code_drafts (
  owner_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  source_code TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS password_change_requests (
  id TEXT PRIMARY KEY,
  status TEXT NOT NULL DEFAULT 'pending',
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL,
  phone TEXT NOT NULL,
  requested_password_hash TEXT NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  created_at INTEGER NOT NULL,
  reviewed_at INTEGER,
  reviewed_by TEXT
);

CREATE TABLE IF NOT EXISTS staff_signup_requests (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  password_hash TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending','approved','rejected')),
  created_at INTEGER NOT NULL,
  reviewed_at INTEGER
);

CREATE TABLE IF NOT EXISTS customer_ticket_access (
  token_hash TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ticket_payment_verifications (
  request_id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  verified_by TEXT NOT NULL,
  verified_at INTEGER NOT NULL
);

-- The Worker expects tickets.request_id to link an uploaded ticket to its request.
ALTER TABLE tickets ADD COLUMN request_id TEXT;
