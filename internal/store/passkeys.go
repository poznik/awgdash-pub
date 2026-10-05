package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"time"
)

// Passkey — ключ входа (WebAuthn): что панель знает об устройстве администратора.
// Приватная часть остаётся в Windows Hello, Touch ID или Face ID и сюда не попадает.
type Passkey struct {
	ID             int64
	AdminID        int64
	CredentialID   string // base64url
	PublicKey      []byte // COSE
	AAGUID         []byte
	Transports     string
	Attestation    string
	SignCount      uint32
	BackupEligible bool
	BackupState    bool
	Name           string
	RPID           string // имя панели, на котором ключ заведён
	CreatedAt      time.Time
	LastUsedAt     time.Time
}

// AddPasskey сохраняет новый ключ администратора.
func (s *Store) AddPasskey(ctx context.Context, p Passkey) (int64, error) {
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, `INSERT INTO passkeys (admin_id, credential_id, public_key, aaguid, transports, attestation, sign_count, backup_eligible, backup_state, name, rp_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.AdminID, p.CredentialID, p.PublicKey, p.AAGUID, p.Transports, p.Attestation, p.SignCount, b2i(p.BackupEligible), b2i(p.BackupState), p.Name, p.RPID, now)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// Passkeys — ключи администратора, свежие сверху.
func (s *Store) Passkeys(ctx context.Context, adminID int64) ([]Passkey, error) {
	return s.passkeysWhere(ctx, `admin_id = ? ORDER BY created_at DESC`, adminID)
}

// PasskeyByCredential ищет ключ по идентификатору, который прислал браузер.
func (s *Store) PasskeyByCredential(ctx context.Context, credentialID string) (Passkey, error) {
	list, err := s.passkeysWhere(ctx, `credential_id = ?`, credentialID)
	if err != nil {
		return Passkey{}, err
	}
	if len(list) == 0 {
		return Passkey{}, sql.ErrNoRows
	}
	return list[0], nil
}

func (s *Store) passkeysWhere(ctx context.Context, cond string, args ...any) ([]Passkey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, admin_id, credential_id, public_key, COALESCE(aaguid, x''), transports, attestation,
		sign_count, backup_eligible, backup_state, name, rp_id, created_at, COALESCE(last_used_at, 0) FROM passkeys WHERE `+cond, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Passkey
	for rows.Next() {
		var p Passkey
		var created, used int64
		var be, bs int
		if err := rows.Scan(&p.ID, &p.AdminID, &p.CredentialID, &p.PublicKey, &p.AAGUID, &p.Transports, &p.Attestation,
			&p.SignCount, &be, &bs, &p.Name, &p.RPID, &created, &used); err != nil {
			return nil, err
		}
		p.BackupEligible, p.BackupState = be == 1, bs == 1
		p.CreatedAt = time.Unix(created, 0)
		if used > 0 {
			p.LastUsedAt = time.Unix(used, 0)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// TouchPasskey отмечает удачный вход: счётчик подписей растёт у ключей, которые его ведут,
// и по нему видно клонирование.
func (s *Store) TouchPasskey(ctx context.Context, id int64, signCount uint32) error {
	_, err := s.db.ExecContext(ctx, `UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?`, signCount, time.Now().Unix(), id)
	return err
}

// RenamePasskey меняет человеческое имя ключа («ноутбук», «телефон»).
func (s *Store) RenamePasskey(ctx context.Context, id, adminID int64, name string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE passkeys SET name = ? WHERE id = ? AND admin_id = ?`, name, id, adminID)
	return err
}

// DeletePasskey убирает ключ. Ограничение по admin_id намеренное: чужой ключ удалить нельзя
// даже подделанным id в форме.
func (s *Store) DeletePasskey(ctx context.Context, id, adminID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM passkeys WHERE id = ? AND admin_id = ?`, id, adminID)
	return err
}

// CountPasskeys — сколько ключей заведено для этого имени панели. Кнопка входа по ключу
// показывается только там, где ключи сработают: ключ с публичного имени на localhost не подойдёт.
// Записи без имени остались от первой версии таблицы — считаем их своими для любого имени.
func (s *Store) CountPasskeys(ctx context.Context, rpID string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM passkeys WHERE rp_id = ? OR rp_id = ''`, rpID).Scan(&n)
	return n, err
}

// WebAuthnHandle возвращает идентификатор администратора для WebAuthn, создавая его при первом
// обращении. Это случайные байты: спецификация просит не класть в user handle имя входа.
func (s *Store) WebAuthnHandle(ctx context.Context, adminID int64) (string, error) {
	var h string
	if err := s.db.QueryRowContext(ctx, `SELECT wa_handle FROM admins WHERE id = ?`, adminID).Scan(&h); err != nil {
		return "", err
	}
	if h != "" {
		return h, nil
	}
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	h = base64.RawURLEncoding.EncodeToString(buf)
	if _, err := s.db.ExecContext(ctx, `UPDATE admins SET wa_handle = ? WHERE id = ?`, h, adminID); err != nil {
		return "", err
	}
	return h, nil
}

// AdminByWebAuthnHandle находит администратора по user handle из ответа браузера.
func (s *Store) AdminByWebAuthnHandle(ctx context.Context, handle string) (Admin, error) {
	return s.adminWhere(ctx, `wa_handle = ?`, handle)
}

// FillPasskeyRPID проставляет имя панели ключам, заведённым до того, как панель начала его
// хранить. Такие ключи считались годными для любого имени, и кнопка входа появлялась там,
// где ключ всё равно не сработал бы.
func (s *Store) FillPasskeyRPID(ctx context.Context, rpID string) (int64, error) {
	if rpID == "" {
		return 0, nil
	}
	res, err := s.db.ExecContext(ctx, `UPDATE passkeys SET rp_id = ? WHERE rp_id = ''`, rpID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
