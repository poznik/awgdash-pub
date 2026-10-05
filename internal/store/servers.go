package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Реестр серверов парка (SPEC FR-10.1). Локальный узел заводится сам при старте,
// удалённые добавляются командой и живут в этой же таблице.

// NewServer — запрос на добавление удалённого узла.
type NewServer struct {
	Slug     string
	Title    string
	SSHHost  string // алиас или host для туннеля, для справки в панели
	KeyPath  string
	NodePort int    // порт, на который смотрит хаб (локальный конец туннеля)
	Country  string // ISO 3166-1 alpha-2 для флага; пусто — угадаем по слагу
	Note     string
}

// AddServer заводит удалённый узел. Порт — обязателен: без него хабу некуда стучаться.
func (s *Store) AddServer(ctx context.Context, n NewServer) (Server, error) {
	slug := strings.ToLower(strings.TrimSpace(n.Slug))
	if slug == "" {
		return Server{}, errors.New("нужен короткий слаг сервера, например hel")
	}
	if n.NodePort <= 0 || n.NodePort > 65535 {
		return Server{}, fmt.Errorf("порт узла %d вне диапазона", n.NodePort)
	}
	title := strings.TrimSpace(n.Title)
	if title == "" {
		title = slug
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO servers (slug, title, transport, ssh_host, ssh_key_path, node_port, enabled, note, country)
		VALUES (?, ?, 'ssh', ?, ?, ?, 1, ?, ?)`, slug, title, n.SSHHost, n.KeyPath, n.NodePort, n.Note, strings.ToUpper(strings.TrimSpace(n.Country)))
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE") {
			return Server{}, fmt.Errorf("сервер %q уже заведён", slug)
		}
		return Server{}, err
	}
	return s.ServerBySlug(ctx, slug)
}

// ServerBySlug ищет сервер по слагу.
func (s *Store) ServerBySlug(ctx context.Context, slug string) (Server, error) {
	list, err := s.Servers(ctx)
	if err != nil {
		return Server{}, err
	}
	for _, v := range list {
		if strings.EqualFold(v.Slug, slug) {
			return v, nil
		}
	}
	return Server{}, ErrNotFound
}

// ServerByID возвращает сервер по id.
func (s *Store) ServerByID(ctx context.Context, id int64) (Server, error) {
	list, err := s.Servers(ctx)
	if err != nil {
		return Server{}, err
	}
	for _, v := range list {
		if v.ID == id {
			return v, nil
		}
	}
	return Server{}, ErrNotFound
}

// RetireServer выводит сервер из парка: опрос прекращается, устройства на его интерфейсах
// перестают считаться работающими (SPEC FR-10.6). Данные остаются — это не удаление.
func (s *Store) RetireServer(ctx context.Context, id int64) error {
	var transport string
	if err := s.db.QueryRowContext(ctx, `SELECT transport FROM servers WHERE id = ?`, id).Scan(&transport); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if transport == "local" {
		return errors.New("сервер панели вывести нельзя — она на нём работает")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE servers SET retired_at = ?, enabled = 0 WHERE id = ?`, time.Now().Unix(), id)
	return err
}

// ReturnServer возвращает выведенный сервер в парк: ошиблись — поправимо.
func (s *Store) ReturnServer(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE servers SET retired_at = NULL, enabled = 1 WHERE id = ?`, id)
	return err
}

// ServerBelongings — что уйдёт вместе с сервером: это показывается до подтверждения (FR-10.7).
type ServerBelongings struct {
	Interfaces int
	Peers      int
	Devices    int
	Users      int
}

// Belongings считает, что привязано к серверу.
func (s *Store) Belongings(ctx context.Context, id int64) (ServerBelongings, error) {
	var b ServerBelongings
	err := s.db.QueryRowContext(ctx, `SELECT
		(SELECT COUNT(*) FROM interfaces WHERE server_id = ?),
		(SELECT COUNT(*) FROM peers p JOIN interfaces i ON i.id = p.interface_id WHERE i.server_id = ?),
		(SELECT COUNT(*) FROM devices d JOIN interfaces i ON i.id = d.interface_id WHERE i.server_id = ? AND d.deleted_at IS NULL),
		(SELECT COUNT(DISTINCT d.user_id) FROM devices d JOIN interfaces i ON i.id = d.interface_id WHERE i.server_id = ? AND d.deleted_at IS NULL)`,
		id, id, id, id).Scan(&b.Interfaces, &b.Peers, &b.Devices, &b.Users)
	return b, err
}

// SetServerEnabled включает или выключает узел: выключенный не опрашивается и не принимает
// записи, но его данные и история остаются.
func (s *Store) SetServerEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE servers SET enabled = ? WHERE id = ?`, b2i(enabled), id)
	return err
}

// DeleteServer убирает удалённый узел из реестра. Локальный удалить нельзя: панель работает
// на нём же, а его интерфейсы и история — основа всего остального.
func (s *Store) DeleteServer(ctx context.Context, id int64) error {
	var transport string
	err := s.db.QueryRowContext(ctx, `SELECT transport FROM servers WHERE id = ?`, id).Scan(&transport)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if transport == "local" {
		return errors.New("локальный сервер удалить нельзя — панель работает на нём")
	}
	var retired sql.NullInt64
	if err := s.db.QueryRowContext(ctx, `SELECT retired_at FROM servers WHERE id = ?`, id).Scan(&retired); err != nil {
		return err
	}
	if !retired.Valid {
		return errors.New("сервер ещё в парке — сначала выведите его: awgdash server retire")
	}
	// Машины больше нет: с ней уходят её интерфейсы, пиры, устройства на них и их история.
	// Пользователи остаются — у них просто не остаётся устройств на этой машине (FR-10.7).
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM traffic_raw WHERE peer_id IN (SELECT p.id FROM peers p JOIN interfaces i ON i.id = p.interface_id WHERE i.server_id = ?)`,
		`DELETE FROM traffic_5m WHERE peer_id IN (SELECT p.id FROM peers p JOIN interfaces i ON i.id = p.interface_id WHERE i.server_id = ?)`,
		`DELETE FROM traffic_1h WHERE peer_id IN (SELECT p.id FROM peers p JOIN interfaces i ON i.id = p.interface_id WHERE i.server_id = ?)`,
		`DELETE FROM peer_state WHERE peer_id IN (SELECT p.id FROM peers p JOIN interfaces i ON i.id = p.interface_id WHERE i.server_id = ?)`,
		`DELETE FROM peers WHERE interface_id IN (SELECT id FROM interfaces WHERE server_id = ?)`,
		`DELETE FROM devices WHERE interface_id IN (SELECT id FROM interfaces WHERE server_id = ?)`,
		// Ноль сюда писать нельзя: колонка ссылается на interfaces(id), и запись с нулём отбивает
		// внешний ключ. «Не задан» в этой схеме — NULL.
		`UPDATE users SET default_interface_id = NULL WHERE default_interface_id IN (SELECT id FROM interfaces WHERE server_id = ?)`,
		`DELETE FROM interfaces WHERE server_id = ?`,
		`DELETE FROM host_metrics WHERE server_id = ?`,
		`DELETE FROM servers WHERE id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// TouchServerSeen отмечает, что узел ответил: по этой метке видно, когда связь пропала.
func (s *Store) TouchServerSeen(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE servers SET last_seen_at = ? WHERE id = ?`, time.Now().Unix(), id)
	return err
}

// SetServerCountry задаёт код страны сервера (для флага в панели и портале).
func (s *Store) SetServerCountry(ctx context.Context, id int64, code string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE servers SET country = ? WHERE id = ?`, strings.ToUpper(strings.TrimSpace(code)), id)
	return err
}

// SetServerTitle меняет человеческое имя сервера — оно видно в выборе сервера и в портале.
func (s *Store) SetServerTitle(ctx context.Context, id int64, title string) error {
	title = strings.TrimSpace(title)
	if title == "" {
		return errors.New("имя сервера не может быть пустым")
	}
	_, err := s.db.ExecContext(ctx, `UPDATE servers SET title = ? WHERE id = ?`, title, id)
	return err
}
