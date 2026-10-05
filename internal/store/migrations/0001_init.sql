-- awgdash · схема M1: серверы, интерфейсы, пиры, статистика, метрики, события, аудит, настройки.
-- Пользователи/устройства/ссылки/админы — в миграциях M2–M3.
CREATE TABLE servers (
  id INTEGER PRIMARY KEY,
  slug TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  transport TEXT NOT NULL DEFAULT 'local',
  ssh_host TEXT, ssh_key_path TEXT, node_port INTEGER,
  enabled INTEGER NOT NULL DEFAULT 1,
  public_ip TEXT, egress_iface TEXT, kernel TEXT, awg_version TEXT, awgdash_version TEXT,
  reboot_required INTEGER NOT NULL DEFAULT 0,
  last_seen_at INTEGER,
  note TEXT NOT NULL DEFAULT ''
);

CREATE TABLE interfaces (
  id INTEGER PRIMARY KEY,
  server_id INTEGER NOT NULL REFERENCES servers(id),
  name TEXT NOT NULL,
  stack TEXT NOT NULL DEFAULT 'awg-bare',
  mode TEXT NOT NULL DEFAULT 'observe',
  conf_path TEXT NOT NULL DEFAULT '',
  subnet TEXT NOT NULL DEFAULT '',
  server_address TEXT NOT NULL DEFAULT '',
  listen_port INTEGER NOT NULL DEFAULT 0,
  mtu INTEGER NOT NULL DEFAULT 0,
  endpoints TEXT NOT NULL DEFAULT '[]',
  server_public_key TEXT NOT NULL DEFAULT '',
  obfuscation TEXT NOT NULL DEFAULT '{}',
  is_awg INTEGER NOT NULL DEFAULT 0,
  default_dns TEXT NOT NULL DEFAULT '1.1.1.1, 8.8.8.8',
  default_keepalive INTEGER NOT NULL DEFAULT 21,
  default_allowed_ips TEXT NOT NULL DEFAULT '0.0.0.0/0',
  psk_enabled INTEGER NOT NULL DEFAULT 1,
  save_config INTEGER NOT NULL DEFAULT 0,
  unit_active INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'unknown',
  conf_mtime INTEGER,
  last_seen_at INTEGER,
  last_verified_at INTEGER,
  last_verify_ok INTEGER,
  last_verify TEXT NOT NULL DEFAULT '{}',
  UNIQUE (server_id, name)
);

CREATE TABLE peers (
  id INTEGER PRIMARY KEY,
  interface_id INTEGER NOT NULL REFERENCES interfaces(id),
  public_key TEXT NOT NULL,
  allowed_ips TEXT NOT NULL DEFAULT '',
  has_psk INTEGER NOT NULL DEFAULT 0,
  device_id INTEGER,
  in_conf INTEGER NOT NULL DEFAULT 0,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  removed_at INTEGER,
  UNIQUE (interface_id, public_key)
);

CREATE TABLE peer_state (
  peer_id INTEGER PRIMARY KEY REFERENCES peers(id),
  rx_counter INTEGER NOT NULL DEFAULT 0,
  tx_counter INTEGER NOT NULL DEFAULT 0,
  last_handshake INTEGER,
  first_handshake_at INTEGER,
  endpoint TEXT NOT NULL DEFAULT '',
  sampled_at INTEGER NOT NULL,
  rx_total INTEGER NOT NULL DEFAULT 0,
  tx_total INTEGER NOT NULL DEFAULT 0,
  resets INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE traffic_raw (ts INTEGER NOT NULL, peer_id INTEGER NOT NULL, rx INTEGER NOT NULL, tx INTEGER NOT NULL, PRIMARY KEY (peer_id, ts)) WITHOUT ROWID;
CREATE INDEX traffic_raw_ts ON traffic_raw(ts);
CREATE TABLE traffic_5m (bucket INTEGER NOT NULL, peer_id INTEGER NOT NULL, rx INTEGER NOT NULL, tx INTEGER NOT NULL, PRIMARY KEY (peer_id, bucket)) WITHOUT ROWID;
CREATE INDEX traffic_5m_bucket ON traffic_5m(bucket);
CREATE TABLE traffic_1h (bucket INTEGER NOT NULL, peer_id INTEGER NOT NULL, rx INTEGER NOT NULL, tx INTEGER NOT NULL, PRIMARY KEY (peer_id, bucket)) WITHOUT ROWID;
CREATE INDEX traffic_1h_bucket ON traffic_1h(bucket);

CREATE TABLE host_metrics (
  server_id INTEGER NOT NULL, ts INTEGER NOT NULL,
  cpu REAL NOT NULL DEFAULT 0, mem_used INTEGER NOT NULL DEFAULT 0, mem_total INTEGER NOT NULL DEFAULT 0,
  swap_used INTEGER NOT NULL DEFAULT 0, swap_total INTEGER NOT NULL DEFAULT 0,
  disk_used INTEGER NOT NULL DEFAULT 0, disk_total INTEGER NOT NULL DEFAULT 0,
  load1 REAL NOT NULL DEFAULT 0, net_rx_bps INTEGER NOT NULL DEFAULT 0, net_tx_bps INTEGER NOT NULL DEFAULT 0,
  net_rx_bytes INTEGER NOT NULL DEFAULT 0, net_tx_bytes INTEGER NOT NULL DEFAULT 0,
  peers_online INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (server_id, ts)
) WITHOUT ROWID;

CREATE TABLE events (
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  kind TEXT NOT NULL,
  severity TEXT NOT NULL DEFAULT 'info',
  server_id INTEGER, interface_id INTEGER, peer_id INTEGER, user_id INTEGER, device_id INTEGER,
  message TEXT NOT NULL DEFAULT '',
  payload TEXT NOT NULL DEFAULT '{}',
  notified_at INTEGER, digest_id INTEGER
);
CREATE INDEX events_ts ON events(ts);

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY,
  ts INTEGER NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target_type TEXT NOT NULL DEFAULT '',
  target_id INTEGER,
  details TEXT NOT NULL DEFAULT '{}',
  ip TEXT NOT NULL DEFAULT ''
);

CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
