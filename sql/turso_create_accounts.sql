-- Applied automatically by the app on every request; kept here for reference.
CREATE TABLE IF NOT EXISTS accounts (
  id TEXT PRIMARY KEY,
  product_name_url TEXT NOT NULL,
  username TEXT NOT NULL,
  password TEXT NOT NULL,
  additional TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now'))
);
