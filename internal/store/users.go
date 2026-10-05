package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"database/sql/driver"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"modernc.org/sqlite"
)

// ulower — регистронезависимость для кириллицы: LOWER и COLLATE NOCASE в SQLite знают только ASCII.
func init() {
	err := sqlite.RegisterDeterministicScalarFunction("ulower", 1, func(_ *sqlite.FunctionContext, args []driver.Value) (driver.Value, error) {
		s, _ := args[0].(string)
		return strings.ToLower(s), nil
	})
	if err != nil {
		panic("регистрация ulower: " + err.Error())
	}
}

// ErrNotFound — запрошенной строки нет (или она удалена).
var ErrNotFound = errors.New("не найдено")

// PurgeAfter — сколько мягко удалённое хранится до окончательной очистки (SPEC FR-2.3, FR-3.4).
const PurgeAfter = 30 * 24 * time.Hour

// User — строка таблицы users. Нулевое время = поле не задано.
type User struct {
	ID                 int64
	Name               string
	Note               string
	SelfService        bool
	MaxDevices         int
	DefaultInterfaceID int64
	// AllowedInterfaces — куда пользователю разрешено сажать устройства из портала.
	// Пусто значит «только интерфейс по умолчанию» (FR-5.2).
	AllowedInterfaces []int64
	Status            string // active | disabled
	ExpiresAt         time.Time
	CreatedAt         time.Time
	UpdatedAt         time.Time
	DeletedAt         time.Time

	// Ниже — вычисляемые поля (заполняются в Users/UserByID/UserByToken).
	Token         string
	Devices       int
	DevicesActive int
	Online        int
	LastHandshake time.Time
	Rx24, Tx24    uint64
}

// Disabled — пользователь выключен администратором.
func (u User) Disabled() bool { return u.Status != "active" }

// Expired — срок действия задан и уже прошёл.
func (u User) Expired() bool { return !u.ExpiresAt.IsZero() && u.ExpiresAt.Before(time.Now()) }

// CreateUser заводит пользователя и сразу выдаёт ему персональную ссылку (FR-2.4).
func (s *Store) CreateUser(ctx context.Context, u User) (int64, string, error) {
	name := strings.TrimSpace(u.Name)
	if name == "" {
		return 0, "", fmt.Errorf("имя пользователя пустое")
	}
	if u.MaxDevices <= 0 {
		u.MaxDevices = 5
	}
	if err := s.nameTaken(ctx, `SELECT 1 FROM users WHERE deleted_at IS NULL AND name_ci = ?`, "пользователь с таким именем уже есть", strings.ToLower(name)); err != nil {
		return 0, "", err
	}
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, `INSERT INTO users (name, name_ci, note, self_service, max_devices, default_interface_id, allowed_interfaces, status, expires_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)`,
		name, strings.ToLower(name), u.Note, b2i(u.SelfService), u.MaxDevices, nullID(u.DefaultInterfaceID),
		formatIDs(u.AllowedInterfaces), nullTime(u.ExpiresAt), now, now)
	if err != nil {
		return 0, "", err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, "", err
	}
	token, err := s.IssueLink(ctx, id)
	if err != nil {
		return 0, "", err
	}
	return id, token, nil
}

// UpdateUser сохраняет редактируемые поля пользователя.
func (s *Store) UpdateUser(ctx context.Context, u User) error {
	name := strings.TrimSpace(u.Name)
	if name == "" {
		return fmt.Errorf("имя пользователя пустое")
	}
	if u.MaxDevices <= 0 {
		u.MaxDevices = 5
	}
	if err := s.nameTaken(ctx, `SELECT 1 FROM users WHERE deleted_at IS NULL AND name_ci = ? AND id <> ?`, "пользователь с таким именем уже есть", strings.ToLower(name), u.ID); err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET name = ?, name_ci = ?, note = ?, self_service = ?, max_devices = ?, default_interface_id = ?, allowed_interfaces = ?, expires_at = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL`,
		name, strings.ToLower(name), u.Note, b2i(u.SelfService), u.MaxDevices, nullID(u.DefaultInterfaceID),
		formatIDs(u.AllowedInterfaces), nullTime(u.ExpiresAt), time.Now().Unix(), u.ID)
	return affected(res, err)
}

// SetUserStatus включает/выключает пользователя (FR-2.2). Пиры снимает вызывающий — это операция на интерфейсе.
func (s *Store) SetUserStatus(ctx context.Context, id int64, status string) error {
	if status != "active" && status != "disabled" {
		return fmt.Errorf("статус пользователя: ожидается active|disabled, получено %q", status)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET status = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`, status, time.Now().Unix(), id)
	return affected(res, err)
}

// DeleteUser — мягкое удаление вместе с устройствами (FR-2.3).
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE users SET deleted_at = ?, status = 'disabled', updated_at = ? WHERE id = ? AND deleted_at IS NULL`, now, now, id)
	if err := affected(res, err); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET status = 'deleted', deleted_at = ?, updated_at = ? WHERE user_id = ? AND deleted_at IS NULL`, now, now, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE user_links SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, now, id); err != nil {
		return err
	}
	return tx.Commit()
}

// RestoreUser возвращает мягко удалённого пользователя и его устройства (в течение PurgeAfter).
// Устройства возвращаются выключенными: включает их администратор осознанно.
func (s *Store) RestoreUser(ctx context.Context, id int64) error {
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE users SET deleted_at = NULL, updated_at = ? WHERE id = ? AND deleted_at IS NOT NULL`, now, id)
	if err := affected(res, err); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE devices SET status = 'disabled', deleted_at = NULL, updated_at = ? WHERE user_id = ? AND deleted_at IS NOT NULL`, now, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_links (user_id, token, created_at) VALUES (?, ?, ?)`, id, mustToken(), now); err != nil {
		return err
	}
	return tx.Commit()
}

// PurgeDeleted окончательно удаляет то, что лежит в корзине дольше `older`.
// Пиры к этому моменту сняты; агрегаты трафика остаются (они привязаны к peer_id).
func (s *Store) PurgeDeleted(ctx context.Context, older time.Duration) (users, devices int64, err error) {
	cut := time.Now().Add(-older).Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE peers SET device_id = NULL WHERE device_id IN (SELECT id FROM devices WHERE deleted_at IS NOT NULL AND deleted_at <= ?)`, cut); err != nil {
		return 0, 0, err
	}
	rd, err := tx.ExecContext(ctx, `DELETE FROM devices WHERE deleted_at IS NOT NULL AND deleted_at <= ?`, cut)
	if err != nil {
		return 0, 0, err
	}
	devices, _ = rd.RowsAffected()
	if _, err := tx.ExecContext(ctx, `DELETE FROM user_links WHERE user_id IN (SELECT id FROM users WHERE deleted_at IS NOT NULL AND deleted_at <= ?)`, cut); err != nil {
		return 0, 0, err
	}
	ru, err := tx.ExecContext(ctx, `DELETE FROM users WHERE deleted_at IS NOT NULL AND deleted_at <= ? AND id NOT IN (SELECT user_id FROM devices)`, cut)
	if err != nil {
		return 0, 0, err
	}
	users, _ = ru.RowsAffected()
	return users, devices, tx.Commit()
}

// ExpiredUsers — люди, у которых срок доступа уже прошёл (для очереди задач на обзоре).
// Возвращает только имя и id: очередь показывает их списком, подробности — в карточке.
func (s *Store) ExpiredUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, expires_at FROM users
		WHERE deleted_at IS NULL AND expires_at IS NOT NULL AND expires_at < ? ORDER BY expires_at`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		var u User
		var exp sql.NullInt64
		if err := rows.Scan(&u.ID, &u.Name, &exp); err != nil {
			return nil, err
		}
		if exp.Valid {
			u.ExpiresAt = time.Unix(exp.Int64, 0)
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// ExpireUsers отключает пользователей с истёкшим сроком и возвращает их id (FR-2.5).
func (s *Store) ExpireUsers(ctx context.Context) ([]int64, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM users WHERE deleted_at IS NULL AND status = 'active' AND expires_at IS NOT NULL AND expires_at <= ?`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, id := range ids {
		if err := s.SetUserStatus(ctx, id, "disabled"); err != nil {
			return nil, err
		}
	}
	return ids, nil
}

// UserFilter — параметры списка пользователей (FR-2.6).
type UserFilter struct {
	Query       string // поиск по имени и заметке
	Status      string // "" | active | disabled
	SelfService bool   // только с самообслуживанием
	Online      bool   // только с хендшейком за OnlineWindow
	Deleted     bool   // корзина вместо активных
	Limit       int
	Offset      int
}

// userColumns — колонки самого пользователя. Всё, что требует обхода устройств, пиров и трафика,
// считается одним запросом на страницу (fillUserStats): раньше на каждую строку списка шло по два
// подзапроса к traffic_raw, и страница на 200 пользователях занимала секунды.
const userColumns = `u.id, u.name, u.note, u.self_service, u.max_devices, COALESCE(u.default_interface_id,0), u.status, COALESCE(u.expires_at,0),
		u.created_at, u.updated_at, COALESCE(u.deleted_at,0), u.allowed_interfaces,
		COALESCE((SELECT l.token FROM user_links l WHERE l.user_id = u.id AND l.revoked_at IS NULL),'')`

// Users возвращает страницу списка и общее число подходящих строк.
func (s *Store) Users(ctx context.Context, f UserFilter) ([]User, int, error) {
	where := []string{}
	args := []any{}
	if f.Deleted {
		where = append(where, `u.deleted_at IS NOT NULL`)
	} else {
		where = append(where, `u.deleted_at IS NULL`)
	}
	if q := strings.TrimSpace(f.Query); q != "" {
		where = append(where, `(u.name_ci LIKE ? ESCAPE '~' OR ulower(u.note) LIKE ? ESCAPE '~')`)
		like := "%" + escapeLike(strings.ToLower(q)) + "%"
		args = append(args, like, like)
	}
	if f.Status != "" {
		where = append(where, `u.status = ?`)
		args = append(args, f.Status)
	}
	if f.SelfService {
		where = append(where, `u.self_service = 1`)
	}
	if f.Online {
		where = append(where, `EXISTS (SELECT 1 FROM devices d JOIN peers p ON p.device_id = d.id JOIN peer_state st ON st.peer_id = p.id
			WHERE d.user_id = u.id AND d.deleted_at IS NULL AND st.last_handshake >= ?)`)
		args = append(args, time.Now().Add(-OnlineWindow).Unix())
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users u WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 50
	}
	q := `SELECT ` + userColumns + ` FROM users u WHERE ` + cond + ` ORDER BY u.name_ci LIMIT ? OFFSET ?`
	qargs := append([]any{}, args...)
	qargs = append(qargs, limit, f.Offset)
	rows, err := s.db.QueryContext(ctx, q, qargs...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if err := s.fillUserStats(ctx, out); err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// fillUserStats добирает онлайн, последний хендшейк и трафик за сутки для страницы списка —
// двумя запросами на всю страницу, а не двумя на каждого пользователя.
func (s *Store) fillUserStats(ctx context.Context, users []User) error {
	if len(users) == 0 {
		return nil
	}
	byID := make(map[int64]*User, len(users))
	ids := make([]any, 0, len(users))
	for i := range users {
		byID[users[i].ID] = &users[i]
		ids = append(ids, users[i].ID)
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")

	drows, err := s.db.QueryContext(ctx, `SELECT user_id, COUNT(*), COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END),0)
		FROM devices WHERE deleted_at IS NULL AND user_id IN (`+ph+`) GROUP BY user_id`, ids...)
	if err != nil {
		return err
	}
	for drows.Next() {
		var id int64
		var total, active int
		if err := drows.Scan(&id, &total, &active); err != nil {
			drows.Close()
			return err
		}
		if u := byID[id]; u != nil {
			u.Devices, u.DevicesActive = total, active
		}
	}
	drows.Close()
	if err := drows.Err(); err != nil {
		return err
	}

	// Пиры пользователей: заодно узнаём, кому какой пир принадлежит — трафик считается по пирам.
	online := time.Now().Add(-OnlineWindow).Unix()
	rows, err := s.db.QueryContext(ctx, `SELECT d.user_id, p.id, COALESCE(st.last_handshake,0)
		FROM devices d JOIN peers p ON p.device_id = d.id LEFT JOIN peer_state st ON st.peer_id = p.id
		WHERE d.deleted_at IS NULL AND d.user_id IN (`+ph+`)`, ids...)
	if err != nil {
		return err
	}
	peerOwner := map[int64]int64{}
	peerIDs := make([]any, 0, len(ids))
	for rows.Next() {
		var userID, peerID, hs int64
		if err := rows.Scan(&userID, &peerID, &hs); err != nil {
			rows.Close()
			return err
		}
		peerOwner[peerID] = userID
		peerIDs = append(peerIDs, peerID)
		if u := byID[userID]; u != nil {
			if hs >= online {
				u.Online++
			}
			if t := fromUnix(hs); t.After(u.LastHandshake) {
				u.LastHandshake = t
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(peerIDs) == 0 {
		return nil
	}

	// Трафик берём прямо по пирам: у traffic_raw первичный ключ (peer_id, ts), и запрос идёт по нему.
	// Если вести тот же запрос от devices через join, планировщик выбирает индекс по времени и
	// прочитывает все записи за сутки — на живом сервере это стоило 15 мс на страницу.
	pph := strings.TrimSuffix(strings.Repeat("?,", len(peerIDs)), ",")
	trows, err := s.db.QueryContext(ctx, `SELECT peer_id, COALESCE(SUM(rx),0), COALESCE(SUM(tx),0) FROM traffic_raw
		WHERE peer_id IN (`+pph+`) AND ts >= ? GROUP BY peer_id`, append(append([]any{}, peerIDs...), time.Now().Unix()-86400)...)
	if err != nil {
		return err
	}
	defer trows.Close()
	for trows.Next() {
		var peerID int64
		var rx, tx uint64
		if err := trows.Scan(&peerID, &rx, &tx); err != nil {
			return err
		}
		if u := byID[peerOwner[peerID]]; u != nil {
			u.Rx24 += rx
			u.Tx24 += tx
		}
	}
	return trows.Err()
}

type scanner interface{ Scan(dest ...any) error }

func scanUser(r scanner) (User, error) {
	var u User
	var self int
	var expires, created, updated, deleted int64
	var allowed string
	err := r.Scan(&u.ID, &u.Name, &u.Note, &self, &u.MaxDevices, &u.DefaultInterfaceID, &u.Status, &expires, &created, &updated, &deleted,
		&allowed, &u.Token)
	if err != nil {
		return User{}, err
	}
	u.AllowedInterfaces = parseIDs(allowed)
	u.SelfService = self == 1
	u.CreatedAt, u.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	u.ExpiresAt, u.DeletedAt = fromUnix(expires), fromUnix(deleted)
	return u, nil
}

// CountUsers — сколько пользователей всего и сколько из них сейчас онлайн. Дашборду нужны
// два числа, а не двести карточек.
func (s *Store) CountUsers(ctx context.Context) (total, online int, err error) {
	if err = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE deleted_at IS NULL`).Scan(&total); err != nil {
		return 0, 0, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(DISTINCT d.user_id) FROM devices d
		JOIN peers p ON p.device_id = d.id JOIN peer_state st ON st.peer_id = p.id
		WHERE d.deleted_at IS NULL AND st.last_handshake >= ?`, time.Now().Add(-OnlineWindow).Unix()).Scan(&online)
	return total, online, err
}

// UserByID возвращает пользователя (в том числе удалённого).
func (s *Store) UserByID(ctx context.Context, id int64) (User, error) {
	return s.userWhere(ctx, `u.id = ?`, id)
}

// UserByName находит активного пользователя по имени (импорт, CLI).
func (s *Store) UserByName(ctx context.Context, name string) (User, error) {
	return s.userWhere(ctx, `u.deleted_at IS NULL AND u.name = ?`, strings.TrimSpace(name))
}

// UserByToken находит пользователя по действующей персональной ссылке (портал, FR-5.3).
func (s *Store) UserByToken(ctx context.Context, token string) (User, error) {
	if token == "" {
		return User{}, ErrNotFound
	}
	return s.userWhere(ctx, `u.deleted_at IS NULL AND EXISTS (SELECT 1 FROM user_links l WHERE l.user_id = u.id AND l.revoked_at IS NULL AND l.token = ?)`, token)
}

func (s *Store) userWhere(ctx context.Context, cond string, args ...any) (User, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users u WHERE `+cond, args...)
	u, err := scanUser(row)
	if errors.Is(err, sql.ErrNoRows) {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	one := []User{u}
	if err := s.fillUserStats(ctx, one); err != nil {
		return User{}, err
	}
	return one[0], nil
}

// ---------- персональные ссылки ----------

// IssueLink гасит прежнюю ссылку пользователя и выдаёт новую (FR-2.4).
func (s *Store) IssueLink(ctx context.Context, userID int64) (string, error) {
	token, err := NewToken()
	if err != nil {
		return "", err
	}
	now := time.Now().Unix()
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE user_links SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`, now, userID); err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO user_links (user_id, token, created_at) VALUES (?, ?, ?)`, userID, token, now); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	return token, nil
}

// TouchLink отмечает использование ссылки порталом.
func (s *Store) TouchLink(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE user_links SET last_used_at = ?, use_count = use_count + 1 WHERE token = ? AND revoked_at IS NULL`, time.Now().Unix(), token)
	return err
}

// NewToken — 256 бит случайности в base64url без выравнивания.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// mustToken — токен для операций внутри транзакции; ошибка crypto/rand означает неработоспособную систему.
func mustToken() string {
	t, err := NewToken()
	if err != nil {
		panic("crypto/rand недоступен: " + err.Error())
	}
	return t
}

// escapeLike экранирует спецсимволы LIKE символом ~ (он же ESCAPE в запросе).
func escapeLike(s string) string {
	return strings.NewReplacer("~", "~~", "%", "~%", "_", "~_").Replace(s)
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.Unix()
}

func fromUnix(v int64) time.Time {
	if v <= 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}

// Allows — разрешён ли интерфейс этому пользователю. Пустой список значит «любой сервер
// парка»: человек не привязан к серверу, привязаны его устройства. Ограничение появляется,
// только если администратор отметил конкретные серверы (FR-5.2).
func (u User) Allows(ifaceID int64) bool {
	if len(u.AllowedInterfaces) == 0 {
		return true
	}
	for _, id := range u.AllowedInterfaces {
		if id == ifaceID {
			return true
		}
	}
	return false
}

// parseIDs разбирает «1,2,3» в список идентификаторов.
func parseIDs(raw string) []int64 {
	var out []int64
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if v, err := strconv.ParseInt(part, 10, 64); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// formatIDs собирает список идентификаторов обратно в строку колонки.
func formatIDs(ids []int64) string {
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		parts = append(parts, strconv.FormatInt(id, 10))
	}
	return strings.Join(parts, ",")
}

// UserOption — строка выбора «кому передать устройство» (FR-3.9, FR-2.7): панели тут нужны
// только имя и сколько у человека устройств, тяжёлые агрегаты списка ради этого не считаются.
type UserOption struct {
	ID      int64
	Name    string
	Devices int
}

// UserOptions — живые пользователи по алфавиту для списков выбора.
func (s *Store) UserOptions(ctx context.Context) ([]UserOption, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT u.id, u.name,
		(SELECT COUNT(*) FROM devices d WHERE d.user_id = u.id AND d.deleted_at IS NULL)
		FROM users u WHERE u.deleted_at IS NULL ORDER BY u.name_ci`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserOption
	for rows.Next() {
		var o UserOption
		if err := rows.Scan(&o.ID, &o.Name, &o.Devices); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}
