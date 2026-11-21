-- Customer-owned saved passenger filters for cross-device autofill.
-- Existing ticket requests and accounts are not modified.
CREATE TABLE IF NOT EXISTS customer_passenger_profiles (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  full_name TEXT NOT NULL,
  age TEXT,
  gender TEXT,
  from_station TEXT,
  to_station TEXT,
  travel_class TEXT,
  updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_customer_passenger_profiles_customer
  ON customer_passenger_profiles(customer_id, updated_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS idx_customer_passenger_profiles_name
  ON customer_passenger_profiles(customer_id, full_name COLLATE NOCASE);
