package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAdminCRUD(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()

	id, err := s.CreateAdmin(ctx, "Admin", "$argon2id$хеш")
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.AdminByUsername(ctx, "admin")
	if err != nil {
		t.Fatal(err)
	}
	if a.ID != id || a.Username != "admin" || a.TOTPEnabled || a.TOTPSecret != "" {
		t.Fatalf("администратор: %+v", a)
	}
	// Имя приводится к нижнему регистру — иначе «Admin» и «admin» стали бы разными людьми.
	if _, err := s.CreateAdmin(ctx, "ADMIN", "$argon2id$другой"); err == nil {
		t.Fatal("создан дубль администратора")
	}
	if _, err := s.AdminByUsername(ctx, "нет-такого"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("поиск несуществующего: %v", err)
	}

	if err := s.SetTOTP(ctx, id, "СЕКРЕТ", true); err != nil {
		t.Fatal(err)
	}
	a, _ = s.AdminByID(ctx, id)
	if !a.TOTPEnabled || a.TOTPSecret != "СЕКРЕТ" {
		t.Fatalf("после SetTOTP: %+v", a)
	}
	if err := s.TouchLogin(ctx, id); err != nil {
		t.Fatal(err)
	}
	a, _ = s.AdminByID(ctx, id)
	if a.LastLoginAt.IsZero() {
		t.Fatal("вход не отмечен")
	}
	list, err := s.Admins(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("список: %+v, err = %v", list, err)
	}
}

func TestSessionsLifecycle(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, _ := s.CreateAdmin(ctx, "admin", "$argon2id$хеш")

	ses, err := s.CreateSession(ctx, id, "10.0.0.1", "Mozilla/5.0")
	if err != nil {
		t.Fatal(err)
	}
	if len(ses.ID) < 40 || len(ses.CSRF) < 40 || ses.ID == ses.CSRF {
		t.Fatalf("сессия: %+v", ses)
	}
	got, err := s.SessionByID(ctx, ses.ID)
	if err != nil || got.AdminID != id || got.CSRF != ses.CSRF {
		t.Fatalf("чтение сессии: %+v, err = %v", got, err)
	}
	if _, err := s.SessionByID(ctx, "чужая"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("чужая сессия: %v", err)
	}

	// Просроченная сессия не отдаётся и подчищается.
	old, _ := s.CreateSession(ctx, id, "10.0.0.2", "ua")
	if _, err := s.DB().ExecContext(ctx, `UPDATE sessions SET expires_at = ? WHERE id = ?`, time.Now().Add(-time.Hour).Unix(), old.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByID(ctx, old.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("просроченная сессия отдана: %v", err)
	}
	var left int
	s.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE id = ?`, old.ID).Scan(&left)
	if left != 0 {
		t.Fatal("просроченная сессия осталась в БД")
	}

	// Смена пароля закрывает все сессии.
	if err := s.SetPassword(ctx, id, "$argon2id$новый"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SessionByID(ctx, ses.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("сессия пережила смену пароля: %v", err)
	}
	a, _ := s.AdminByID(ctx, id)
	if a.PasswordHash != "$argon2id$новый" {
		t.Fatalf("хеш не обновлён: %+v", a)
	}
}

func TestSessionTouchAndPurge(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, _ := s.CreateAdmin(ctx, "admin", "$argon2id$хеш")
	ses, _ := s.CreateSession(ctx, id, "10.0.0.1", "ua")

	// Свежая сессия не переписывается на каждом запросе.
	before, _ := s.SessionByID(ctx, ses.ID)
	if err := s.TouchSession(ctx, before); err != nil {
		t.Fatal(err)
	}
	after, _ := s.SessionByID(ctx, ses.ID)
	if !after.ExpiresAt.Equal(before.ExpiresAt) {
		t.Fatal("срок продлён раньше времени")
	}

	// Сессия, которой не касались два часа: сдвигаем её время в БД назад — так же выглядит
	// вчерашний вход. Продление возвращает полный срок.
	shifted := time.Now().Add(-2 * time.Hour)
	if _, err := s.DB().ExecContext(ctx, `UPDATE sessions SET last_seen_at = ?, expires_at = ? WHERE id = ?`,
		shifted.Unix(), shifted.Add(SessionTTL).Unix(), ses.ID); err != nil {
		t.Fatal(err)
	}
	stale, _ := s.SessionByID(ctx, ses.ID)
	if err := s.TouchSession(ctx, stale); err != nil {
		t.Fatal(err)
	}
	after, _ = s.SessionByID(ctx, ses.ID)
	if !after.ExpiresAt.After(stale.ExpiresAt) {
		t.Fatalf("срок не продлён: было %s, стало %s", stale.ExpiresAt, after.ExpiresAt)
	}

	if n, err := s.PurgeSessions(ctx); err != nil || n != 0 {
		t.Fatalf("PurgeSessions вычистил живое: %d, err = %v", n, err)
	}
	if err := s.DeleteSessionsOf(ctx, id); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.Sessions(ctx, id); len(list) != 0 {
		t.Fatalf("сессии остались: %+v", list)
	}
}

func TestDeleteAdmin(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	first, _ := s.CreateAdmin(ctx, "admin", "$argon2id$хеш")
	if err := s.DeleteAdmin(ctx, first); err == nil {
		t.Fatal("удалён последний администратор — входить стало бы некому")
	}
	second, err := s.CreateAdmin(ctx, "временный", "$argon2id$хеш2")
	if err != nil {
		t.Fatal(err)
	}
	ses, err := s.CreateSession(ctx, second, "10.0.0.5", "curl")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAdmin(ctx, second); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AdminByUsername(ctx, "временный"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("администратор остался: %v", err)
	}
	if _, err := s.SessionByID(ctx, ses.ID); !errors.Is(err, ErrNotFound) {
		t.Fatal("сессия удалённого администратора осталась рабочей")
	}
	if list, _ := s.Admins(ctx); len(list) != 1 {
		t.Fatalf("администраторов осталось: %d", len(list))
	}
}
