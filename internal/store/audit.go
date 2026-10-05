package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Actor — кто выполнил действие: admin, user:<id>, system (SPEC FR-12.1).
const (
	ActorAdmin  = "admin"
	ActorSystem = "system"
)

// UserActor — актор для действий из портала.
func UserActor(userID int64) string {
	return "user:" + itoa(userID)
}

// AuditEntry — строка журнала действий. Секретов в Details быть не должно (FR-4.6).
type AuditEntry struct {
	ID         int64
	TS         time.Time
	Actor      string
	Action     string
	TargetType string
	TargetID   int64
	Details    map[string]any
	IP         string
}

// Потолки записи (FR-12.1a). Аудит принимает данные и от неаутентифицированных запросов —
// неудачный вход пишет присланное имя, — поэтому без ограничения одна попытка заполняет
// журнал произвольным объёмом.
const (
	maxDetailValue = 512     // символов в одном строковом значении
	maxDetails     = 8 << 10 // байт во всём наборе деталей
)

// AddAudit пишет запись журнала.
func (s *Store) AddAudit(ctx context.Context, e AuditEntry) error {
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	if e.Actor == "" {
		e.Actor = ActorSystem
	}
	details := "{}"
	if len(e.Details) > 0 {
		b, err := json.Marshal(scrub(e.Details))
		if err != nil {
			return err
		}
		if len(b) > maxDetails {
			b, err = json.Marshal(map[string]any{"trimmed": fmt.Sprintf("детали не сохранены: %d байт", len(b))})
			if err != nil {
				return err
			}
		}
		details = string(b)
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO audit_log (ts, actor, action, target_type, target_id, details, ip) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.TS.Unix(), e.Actor, e.Action, e.TargetType, nullID(e.TargetID), details, e.IP)
	return err
}

// AuditFilter — фильтры страницы «События и аудит» (FR-12.2).
type AuditFilter struct {
	Actor      string
	Action     string
	TargetType string
	TargetID   int64
	Since      time.Time
	Limit      int
	Offset     int
}

// Audit возвращает записи журнала, новые сверху.
func (s *Store) Audit(ctx context.Context, f AuditFilter) ([]AuditEntry, error) {
	where := []string{"1 = 1"}
	args := []any{}
	if f.Actor != "" {
		where = append(where, "actor = ?")
		args = append(args, f.Actor)
	}
	if f.Action != "" {
		where = append(where, "action = ?")
		args = append(args, f.Action)
	}
	if f.TargetType != "" {
		where = append(where, "target_type = ?")
		args = append(args, f.TargetType)
	}
	if f.TargetID != 0 {
		where = append(where, "target_id = ?")
		args = append(args, f.TargetID)
	}
	if !f.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, f.Since.Unix())
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	}
	args = append(args, limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, actor, action, target_type, COALESCE(target_id,0), details, ip
		FROM audit_log WHERE `+strings.Join(where, " AND ")+` ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ts int64
		var details string
		if err := rows.Scan(&e.ID, &ts, &e.Actor, &e.Action, &e.TargetType, &e.TargetID, &details, &e.IP); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		json.Unmarshal([]byte(details), &e.Details)
		out = append(out, e)
	}
	return out, rows.Err()
}

// CountAudit — сколько всего записей журнала действий (для пагинации).
func (s *Store) CountAudit(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log`).Scan(&n)
	return n, err
}

// secretKeys — поля, которые не должны попадать ни в журнал, ни в события (FR-4.6).
var secretKeys = []string{"private_key", "preshared_key", "psk", "password", "token", "session"}

// scrub выкидывает из деталей всё, что похоже на секрет: журнал читают и пересылают.
func scrub(in map[string]any) map[string]any {
	out := make(map[string]any, len(in))
	for k, v := range in {
		lower := strings.ToLower(k)
		hidden := false
		for _, s := range secretKeys {
			if strings.Contains(lower, s) {
				hidden = true
				break
			}
		}
		if hidden {
			out[k] = "(скрыто)"
			continue
		}
		if m, ok := v.(map[string]any); ok {
			out[k] = scrub(m)
			continue
		}
		if str, ok := v.(string); ok {
			out[k] = TrimRunes(str, maxDetailValue)
			continue
		}
		out[k] = v
	}
	return out
}

// TrimRunes обрезает строку по символам, а не по байтам: кириллица занимает два байта,
// и обрезка по длине разрезала бы букву пополам.
func TrimRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// PurgeJournals удаляет записи аудита и события старше keep (FR-12.2a). Возвращает,
// сколько строк ушло из каждой таблицы.
func (s *Store) PurgeJournals(ctx context.Context, keep time.Duration) (int64, int64, error) {
	if keep <= 0 {
		return 0, 0, nil
	}
	before := time.Now().Add(-keep).Unix()
	res, err := s.db.ExecContext(ctx, `DELETE FROM audit_log WHERE ts < ?`, before)
	if err != nil {
		return 0, 0, err
	}
	audits, _ := res.RowsAffected()
	res, err = s.db.ExecContext(ctx, `DELETE FROM events WHERE ts < ?`, before)
	if err != nil {
		return audits, 0, err
	}
	events, _ := res.RowsAffected()
	return audits, events, nil
}

func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
