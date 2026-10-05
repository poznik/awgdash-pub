-- awgdash · схема M2: пользователи, персональные ссылки, устройства.
-- Статистика устройства не дублируется: она лежит в peers/peer_state и связывается через peers.device_id.
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  self_service INTEGER NOT NULL DEFAULT 0,
  max_devices INTEGER NOT NULL DEFAULT 5,
  default_interface_id INTEGER REFERENCES interfaces(id),
  status TEXT NOT NULL DEFAULT 'active',      -- active | disabled
  expires_at INTEGER,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted_at INTEGER
);
CREATE UNIQUE INDEX users_name ON users(name) WHERE deleted_at IS NULL;
CREATE INDEX users_status ON users(status) WHERE deleted_at IS NULL;

CREATE TABLE user_links (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  token TEXT NOT NULL UNIQUE,                 -- 256 бит, base64url
  created_at INTEGER NOT NULL,
  revoked_at INTEGER,
  last_used_at INTEGER,
  use_count INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX user_links_active ON user_links(user_id) WHERE revoked_at IS NULL;

CREATE TABLE devices (
  id INTEGER PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  interface_id INTEGER NOT NULL REFERENCES interfaces(id),
  name TEXT NOT NULL,
  preset TEXT NOT NULL DEFAULT 'phone',       -- phone | router | custom
  private_key TEXT NOT NULL DEFAULT '',       -- секрет: не логировать, не отдавать в события
  public_key TEXT NOT NULL,
  preshared_key TEXT NOT NULL DEFAULT '',     -- секрет
  address TEXT NOT NULL,                      -- без маски: 10.20.0.7
  overrides TEXT NOT NULL DEFAULT '{}',       -- json: allowed_ips, dns, mtu, keepalive
  status TEXT NOT NULL DEFAULT 'active',      -- active | disabled | deleted
  created_by TEXT NOT NULL DEFAULT 'admin',   -- admin | user | import
  note TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  deleted_at INTEGER,                         -- мягкое удаление; окончательная очистка через 30 дней
  issued_at INTEGER,                          -- когда конфиг последний раз выдавали
  issue_count INTEGER NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX devices_pub ON devices(interface_id, public_key) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX devices_addr ON devices(interface_id, address) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX devices_name ON devices(user_id, name) WHERE deleted_at IS NULL;
CREATE INDEX devices_user ON devices(user_id) WHERE deleted_at IS NULL;
CREATE INDEX devices_iface ON devices(interface_id) WHERE deleted_at IS NULL;
