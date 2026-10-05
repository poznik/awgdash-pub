package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// historyTables — таблицы, которые не попадают в конфигурационный бэкап: они большие и
// восстановимы наблюдением, а нужен он ради состояния панели и ключей (SPEC FR-9.1).
var historyTables = []string{"traffic_raw", "traffic_5m", "traffic_1h", "host_metrics", "events"}

// SnapshotTo делает согласованную копию базы в отдельный файл. VACUUM INTO берёт снимок
// без остановки панели: копировать файл на живой WAL-базе нельзя.
func (s *Store) SnapshotTo(ctx context.Context, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	// VACUUM INTO отказывается писать в существующий файл.
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		return fmt.Errorf("снимок БД в %s: %w", path, err)
	}
	return nil
}

// StripHistory убирает из копии базы таблицы наблюдения. Работает с файлом-снимком,
// живую базу не трогает.
func StripHistory(ctx context.Context, path string) error {
	st, err := Open(path)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, t := range historyTables {
		if _, err := st.db.ExecContext(ctx, `DELETE FROM `+t); err != nil {
			return fmt.Errorf("очистка %s: %w", t, err)
		}
	}
	if _, err := st.db.ExecContext(ctx, `VACUUM`); err != nil {
		return fmt.Errorf("сжатие копии: %w", err)
	}
	return nil
}

// SchemaVersion — последняя применённая миграция: восстановление на панели старее бэкапа
// закончилось бы непонятной ошибкой на первом же запросе.
func (s *Store) SchemaVersion(ctx context.Context) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1`).Scan(&v)
	return v, err
}
