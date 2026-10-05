package store

import (
	"context"
	"encoding/json"
	"time"
)

// NotifyConfig — настройки оповещателя (SPEC FR-8.2, FR-8.3, FR-13.3). Лежит одной записью
// в settings: страница настроек читает и пишет её целиком, миграции под каждый порог не нужны.
type NotifyConfig struct {
	Enabled      bool     `json:"enabled"`
	QuietEnabled bool     `json:"quiet_enabled"`
	QuietFrom    int      `json:"quiet_from"` // час начала тишины в зоне панели
	QuietTo      int      `json:"quiet_to"`
	Off          []string `json:"off"`         // виды событий, выключенные администратором
	SpikeGB      float64  `json:"spike_gb"`    // порог traffic_spike за час
	DiskHigh     int      `json:"disk_high"`   // проценты
	MemHigh      int      `json:"mem_high"`    // проценты
	LoadHigh     float64  `json:"load_high"`   // load average за минуту
	DroughtMin   int      `json:"drought_min"` // сколько устройств за сутки делает засуху засухой
}

// DefaultNotify — значения по умолчанию. Пороги взяты из ТЗ; тихий режим выключен, потому что
// молчать ночью о падении интерфейса опаснее, чем разбудить.
func DefaultNotify() NotifyConfig {
	return NotifyConfig{
		Enabled: true, QuietEnabled: false, QuietFrom: 23, QuietTo: 8,
		SpikeGB: 5, DiskHigh: 85, MemHigh: 90, LoadHigh: 2, DroughtMin: 3,
	}
}

const notifyKey = "notify"

// Notify читает настройки оповещателя; пустая запись — значения по умолчанию.
func (s *Store) Notify(ctx context.Context) (NotifyConfig, error) {
	cfg := DefaultNotify()
	raw, err := s.Setting(ctx, notifyKey)
	if err != nil || raw == "" {
		return cfg, err
	}
	// Разбор поверх умолчаний: новое поле в структуре не обнуляет старую запись.
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		return DefaultNotify(), err
	}
	return cfg, nil
}

// SetNotify сохраняет настройки оповещателя.
func (s *Store) SetNotify(ctx context.Context, cfg NotifyConfig) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return s.SetSetting(ctx, notifyKey, string(raw))
}

// IsOff — выключен ли вид события.
func (c NotifyConfig) IsOff(kind string) bool {
	for _, k := range c.Off {
		if k == kind {
			return true
		}
	}
	return false
}

// Quiet — попадает ли момент в тихие часы. Окно может пересекать полночь (23→8).
func (c NotifyConfig) Quiet(t time.Time) bool {
	if !c.QuietEnabled || c.QuietFrom == c.QuietTo {
		return false
	}
	h := t.Hour()
	if c.QuietFrom < c.QuietTo {
		return h >= c.QuietFrom && h < c.QuietTo
	}
	return h >= c.QuietFrom || h < c.QuietTo
}

// PendingEvents — события, ещё не ушедшие в Telegram, от старых к новым.
func (s *Store) PendingEvents(ctx context.Context, limit int) ([]Event, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, kind, severity, COALESCE(server_id,0), COALESCE(interface_id,0),
		COALESCE(peer_id,0), COALESCE(user_id,0), COALESCE(device_id,0), message, payload
		FROM events WHERE notified_at IS NULL ORDER BY ts, id LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var ts int64
		var payload string
		if err := rows.Scan(&e.ID, &ts, &e.Kind, &e.Severity, &e.ServerID, &e.InterfaceID, &e.PeerID, &e.UserID, &e.DeviceID, &e.Message, &payload); err != nil {
			return nil, err
		}
		e.TS = time.Unix(ts, 0)
		e.Payload = json.RawMessage(payload)
		out = append(out, e)
	}
	return out, rows.Err()
}

// MarkNotified отмечает события отправленными (или сознательно пропущенными: выключенный вид,
// подавленный повтор — второй раз к ним возвращаться незачем).
func (s *Store) MarkNotified(ctx context.Context, ids []int64, at time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	args := append([]any{at.Unix()}, toArgs(ids)...)
	_, err := s.db.ExecContext(ctx, `UPDATE events SET notified_at = ? WHERE id IN (`+placeholders(len(ids))+`)`, args...)
	return err
}

// SkipEventsBefore закрывает старую очередь без отправки. Нужно на первом запуске бота: иначе
// в чат уедет вся история, накопленная до того, как у панели появился токен.
func (s *Store) SkipEventsBefore(ctx context.Context, t time.Time) (int64, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE events SET notified_at = ? WHERE notified_at IS NULL AND ts < ?`, time.Now().Unix(), t.Unix())
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}
