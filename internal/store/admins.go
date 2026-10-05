package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SessionTTL — срок жизни сессии админки; при каждом запросе продлевается (FR-13.1).
const SessionTTL = 30 * 24 * time.Hour

// Admin — администратор панели. PasswordHash и TOTPSecret — секреты.
type Admin struct {
	ID           int64
	Username     string
	PasswordHash string
	TOTPSecret   string
	TOTPEnabled  bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
	LastLoginAt  time.Time
}

// Session — вход администратора с устройства.
type Session struct {
	ID         string
	AdminID    int64
	CSRF       string
	CreatedAt  time.Time
	ExpiresAt  time.Time
	LastSeenAt time.Time
	IP         string
	UA         string
}

// Expired — сессия просрочена.
func (s Session) Expired() bool { return time.Now().After(s.ExpiresAt) }

// CreateAdmin заводит администратора с готовым хешем пароля.
func (s *Store) CreateAdmin(ctx context.Context, username, passwordHash string) (int64, error) {
	username = strings.TrimSpace(strings.ToLower(username))
	if username == "" {
		return 0, fmt.Errorf("имя администратора пустое")
	}
	if passwordHash == "" {
		return 0, fmt.Errorf("пустой хеш пароля")
	}
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, `INSERT INTO admins (username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?)`,
		username, passwordHash, now, now)
	if err != nil {
		if strings.Contains(err.Error(), "admins.username") {
			return 0, fmt.Errorf("администратор %q уже есть", username)
		}
		return 0, err
	}
	return res.LastInsertId()
}

// AdminByUsername ищет администратора по имени (регистр не важен).
func (s *Store) AdminByUsername(ctx context.Context, username string) (Admin, error) {
	return s.adminWhere(ctx, `username = ?`, strings.TrimSpace(strings.ToLower(username)))
}

// AdminByID возвращает администратора по id.
func (s *Store) AdminByID(ctx context.Context, id int64) (Admin, error) {
	return s.adminWhere(ctx, `id = ?`, id)
}

func (s *Store) adminWhere(ctx context.Context, cond string, args ...any) (Admin, error) {
	var a Admin
	var enabled int
	var created, updated, login sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id, username, password_hash, totp_secret, totp_enabled, created_at, updated_at, last_login_at FROM admins WHERE `+cond, args...).
		Scan(&a.ID, &a.Username, &a.PasswordHash, &a.TOTPSecret, &enabled, &created, &updated, &login)
	if errors.Is(err, sql.ErrNoRows) {
		return Admin{}, ErrNotFound
	}
	if err != nil {
		return Admin{}, err
	}
	a.TOTPEnabled = enabled == 1
	a.CreatedAt, a.UpdatedAt, a.LastLoginAt = fromUnix(created.Int64), fromUnix(updated.Int64), fromUnix(login.Int64)
	return a, nil
}

// Admins перечисляет администраторов (для CLI и страницы настроек).
func (s *Store) Admins(ctx context.Context) ([]Admin, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, username, password_hash, totp_secret, totp_enabled, created_at, updated_at, last_login_at FROM admins ORDER BY username`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Admin
	for rows.Next() {
		var a Admin
		var enabled int
		var created, updated, login sql.NullInt64
		if err := rows.Scan(&a.ID, &a.Username, &a.PasswordHash, &a.TOTPSecret, &enabled, &created, &updated, &login); err != nil {
			return nil, err
		}
		a.TOTPEnabled = enabled == 1
		a.CreatedAt, a.UpdatedAt, a.LastLoginAt = fromUnix(created.Int64), fromUnix(updated.Int64), fromUnix(login.Int64)
		out = append(out, a)
	}
	return out, rows.Err()
}

// SetPassword меняет хеш пароля и гасит все сессии администратора: смена пароля выкидывает
// того, кто уже вошёл с чужого устройства.
func (s *Store) SetPassword(ctx context.Context, adminID int64, passwordHash string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE admins SET password_hash = ?, updated_at = ? WHERE id = ?`, passwordHash, time.Now().Unix(), adminID)
	if err := affected(res, err); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE admin_id = ?`, adminID); err != nil {
		return err
	}
	return tx.Commit()
}

// SetTOTP сохраняет секрет второго фактора; enabled=false со сбросом секрета отключает его.
func (s *Store) SetTOTP(ctx context.Context, adminID int64, secret string, enabled bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE admins SET totp_secret = ?, totp_enabled = ?, updated_at = ? WHERE id = ?`,
		secret, b2i(enabled), time.Now().Unix(), adminID)
	return affected(res, err)
}

// DeleteAdmin удаляет администратора вместе с его сессиями. Последнего удалить нельзя:
// иначе в панель некому будет войти.
func (s *Store) DeleteAdmin(ctx context.Context, id int64) error {
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM admins`).Scan(&total); err != nil {
		return err
	}
	if total <= 1 {
		return fmt.Errorf("это последний администратор — удалять некого будет пускать")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE admin_id = ?`, id); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM admins WHERE id = ?`, id)
	if err := affected(res, err); err != nil {
		return err
	}
	return tx.Commit()
}

// TouchLogin отмечает удачный вход.
func (s *Store) TouchLogin(ctx context.Context, adminID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE admins SET last_login_at = ? WHERE id = ?`, time.Now().Unix(), adminID)
	return err
}

// ---------- сессии ----------

// CreateSession выдаёт сессию на SessionTTL и возвращает её вместе с CSRF-токеном.
func (s *Store) CreateSession(ctx context.Context, adminID int64, ip, ua string) (Session, error) {
	id, err := NewToken()
	if err != nil {
		return Session{}, err
	}
	csrf, err := NewToken()
	if err != nil {
		return Session{}, err
	}
	now := time.Now()
	ses := Session{ID: id, AdminID: adminID, CSRF: csrf, CreatedAt: now, ExpiresAt: now.Add(SessionTTL), LastSeenAt: now, IP: ip, UA: trim(ua, 200)}
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions (id, admin_id, csrf, created_at, expires_at, last_seen_at, ip, ua) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		ses.ID, ses.AdminID, ses.CSRF, ses.CreatedAt.Unix(), ses.ExpiresAt.Unix(), ses.LastSeenAt.Unix(), ses.IP, ses.UA)
	if err != nil {
		return Session{}, err
	}
	return ses, nil
}

// SessionByID возвращает живую сессию; просроченная удаляется и считается отсутствующей.
func (s *Store) SessionByID(ctx context.Context, id string) (Session, error) {
	if id == "" {
		return Session{}, ErrNotFound
	}
	var ses Session
	var created, expires, seen int64
	err := s.db.QueryRowContext(ctx, `SELECT id, admin_id, csrf, created_at, expires_at, last_seen_at, ip, ua FROM sessions WHERE id = ?`, id).
		Scan(&ses.ID, &ses.AdminID, &ses.CSRF, &created, &expires, &seen, &ses.IP, &ses.UA)
	if errors.Is(err, sql.ErrNoRows) {
		return Session{}, ErrNotFound
	}
	if err != nil {
		return Session{}, err
	}
	ses.CreatedAt, ses.ExpiresAt, ses.LastSeenAt = time.Unix(created, 0), time.Unix(expires, 0), time.Unix(seen, 0)
	if ses.Expired() {
		s.DeleteSession(ctx, id)
		return Session{}, ErrNotFound
	}
	return ses, nil
}

// TouchSession продлевает сессию; запись в БД идёт не чаще раза в час, чтобы не писать на каждый запрос.
func (s *Store) TouchSession(ctx context.Context, ses Session) error {
	if time.Since(ses.LastSeenAt) < time.Hour {
		return nil
	}
	now := time.Now()
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?`, now.Unix(), now.Add(SessionTTL).Unix(), ses.ID)
	return err
}

// DeleteSession выкидывает одну сессию (выход).
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// DeleteSessionsOf выкидывает все сессии администратора («выйти везде»).
func (s *Store) DeleteSessionsOf(ctx context.Context, adminID int64) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE admin_id = ?`, adminID)
	return err
}

// PurgeSessions удаляет просроченные сессии.
func (s *Store) PurgeSessions(ctx context.Context) (int64, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, time.Now().Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Sessions перечисляет живые сессии администратора (страница настроек).
func (s *Store) Sessions(ctx context.Context, adminID int64) ([]Session, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, admin_id, csrf, created_at, expires_at, last_seen_at, ip, ua FROM sessions WHERE admin_id = ? AND expires_at >= ? ORDER BY last_seen_at DESC`,
		adminID, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		var ses Session
		var created, expires, seen int64
		if err := rows.Scan(&ses.ID, &ses.AdminID, &ses.CSRF, &created, &expires, &seen, &ses.IP, &ses.UA); err != nil {
			return nil, err
		}
		ses.CreatedAt, ses.ExpiresAt, ses.LastSeenAt = time.Unix(created, 0), time.Unix(expires, 0), time.Unix(seen, 0)
		out = append(out, ses)
	}
	return out, rows.Err()
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
