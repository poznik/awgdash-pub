-- awgdash · схема M3: администраторы панели и их сессии (SPEC FR-13.1).
-- Пароль — argon2id, второй фактор — TOTP; секрет TOTP хранится как есть, его нельзя хешировать.
CREATE TABLE admins (
  id INTEGER PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  totp_secret TEXT NOT NULL DEFAULT '',
  totp_enabled INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_login_at INTEGER
);

CREATE TABLE sessions (
  id TEXT PRIMARY KEY,                -- 256 бит base64url, лежит в куке
  admin_id INTEGER NOT NULL REFERENCES admins(id),
  csrf TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  ip TEXT NOT NULL DEFAULT '',
  ua TEXT NOT NULL DEFAULT ''
);
CREATE INDEX sessions_admin ON sessions(admin_id);
CREATE INDEX sessions_expires ON sessions(expires_at);
