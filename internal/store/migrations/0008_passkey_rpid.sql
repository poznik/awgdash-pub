-- Ключ WebAuthn привязан к имени, по которому его завели: ключ с panel.example.com не сработает
-- на localhost и наоборот. Имя нужно, чтобы не показывать кнопку входа там, где ключей нет.
ALTER TABLE passkeys ADD COLUMN rp_id TEXT NOT NULL DEFAULT '';
