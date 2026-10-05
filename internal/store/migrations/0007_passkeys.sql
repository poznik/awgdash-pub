-- awgdash · ключи входа (passkeys, WebAuthn): вход по Windows Hello, Touch ID, Face ID.
-- Публичный ключ и счётчик подписей хранятся как есть: секрета в них нет, приватная часть
-- никогда не покидает устройство.
CREATE TABLE passkeys (
  id INTEGER PRIMARY KEY,
  admin_id INTEGER NOT NULL REFERENCES admins(id),
  credential_id TEXT NOT NULL UNIQUE,     -- base64url, как приходит от браузера
  public_key BLOB NOT NULL,               -- COSE
  aaguid BLOB,
  transports TEXT NOT NULL DEFAULT '',
  attestation TEXT NOT NULL DEFAULT '',
  sign_count INTEGER NOT NULL DEFAULT 0,
  backup_eligible INTEGER NOT NULL DEFAULT 0,
  backup_state INTEGER NOT NULL DEFAULT 0,
  name TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  last_used_at INTEGER
);
CREATE INDEX passkeys_admin ON passkeys(admin_id);

-- Идентификатор пользователя для WebAuthn: случайные 16 байт, не связанные с именем входа.
-- Спецификация просит не класть туда персональные данные.
ALTER TABLE admins ADD COLUMN wa_handle TEXT NOT NULL DEFAULT '';
