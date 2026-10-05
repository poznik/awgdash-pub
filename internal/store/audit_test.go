package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Записи журнала живут ограниченный срок (FR-12.2a): без чистки audit_log и events росли
// бесконечно, а наполнять их может и неаутентифицированный запрос.
func TestPurgeJournals(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	now := time.Now()
	old := now.AddDate(0, 0, -200)

	if err := st.AddAudit(ctx, AuditEntry{TS: old, Actor: ActorSystem, Action: "admin.login_failed"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddAudit(ctx, AuditEntry{TS: now, Actor: ActorAdmin, Action: "device.create"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddEvent(ctx, Event{TS: old, Kind: "counters_reset", Message: "давнее"}); err != nil {
		t.Fatal(err)
	}
	if err := st.AddEvent(ctx, Event{TS: now, Kind: "device_created", Message: "свежее"}); err != nil {
		t.Fatal(err)
	}

	audits, events, err := st.PurgeJournals(ctx, 180*24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if audits != 1 || events != 1 {
		t.Fatalf("удалено записей: аудит %d, события %d — ожидалось по одной", audits, events)
	}
	var left int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 1 {
		t.Fatalf("в аудите осталось %d записей, ожидалась одна", left)
	}
}

// Детали записи ограничены по размеру (FR-12.1a): длинное значение обрезается, а слишком
// большой набор заменяется отметкой.
func TestAuditDetailsAreCapped(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	if err := st.AddAudit(ctx, AuditEntry{Actor: ActorSystem, Action: "admin.login_failed",
		Details: map[string]any{"username": strings.Repeat("Ы", 5000)}}); err != nil {
		t.Fatal(err)
	}
	var details string
	if err := st.DB().QueryRow(`SELECT details FROM audit_log`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if len(details) > maxDetails {
		t.Fatalf("детали заняли %d байт при потолке %d", len(details), maxDetails)
	}
	if !strings.Contains(details, "…") {
		t.Fatalf("значение не обрезано: %s", details)
	}
}

// Секреты по-прежнему не попадают в журнал, а обрезка их не «раскрывает».
func TestAuditKeepsSecretsOut(t *testing.T) {
	ctx := context.Background()
	st := openTest(t)
	if err := st.AddAudit(ctx, AuditEntry{Actor: ActorAdmin, Action: "device.create",
		Details: map[string]any{"private_key": "СЕКРЕТ", "name": "телефон"}}); err != nil {
		t.Fatal(err)
	}
	var details string
	if err := st.DB().QueryRow(`SELECT details FROM audit_log`).Scan(&details); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(details, "СЕКРЕТ") {
		t.Fatalf("приватный ключ попал в журнал: %s", details)
	}
}
