package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Пресеты устройства (SPEC FR-4.3).
const (
	PresetPhone  = "phone"
	PresetRouter = "router"
	PresetCustom = "custom"
)

// Overrides — переопределения устройства поверх умолчаний интерфейса. Пустое поле = взять умолчание.
type Overrides struct {
	AllowedIPs string `json:"allowed_ips,omitempty"`
	DNS        string `json:"dns,omitempty"`
	MTU        int    `json:"mtu,omitempty"`
	Keepalive  int    `json:"keepalive,omitempty"`
}

// Device — строка таблицы devices. PrivateKey и PresharedKey — секреты: не логировать, не отдавать в события.
type Device struct {
	ID           int64
	UserID       int64
	InterfaceID  int64
	Name         string
	Preset       string
	PrivateKey   string
	PublicKey    string
	PresharedKey string
	Address      string
	Overrides    Overrides
	Status       string // active | disabled | deleted
	CreatedBy    string // admin | user | import
	Note         string
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    time.Time
	IssuedAt     time.Time
	IssueCount   int

	// Вычисляемые поля (из peers/peer_state, заполняются при выборке).
	// ServerRetired — сервер устройства выведен из парка: конфиг больше не подключится (FR-10.6).
	ServerRetired bool
	UserName      string
	InterfaceName string
	PeerID        int64
	OnInterface   bool // пир найден в рантайме интерфейса
	LastHandshake time.Time
	Endpoint      string
	RxTotal       uint64
	TxTotal       uint64
	Rx24, Tx24    uint64
}

// Active — устройство должно стоять на интерфейсе.
func (d Device) Active() bool { return d.Status == "active" && d.DeletedAt.IsZero() }

// HasKey — панель знает приватный ключ и может собрать конфиг. Усыновлённые и импортированные
// без ключа пиры его не имеют: панель ими управляет, но выдать человеку конфиг не может —
// приватная часть осталась только на устройстве (FR-1.6, FR-11.1).
func (d Device) HasKey() bool { return d.PrivateKey != "" }

// Online — хендшейк не старше OnlineWindow.
func (d Device) Online() bool {
	return !d.LastHandshake.IsZero() && time.Since(d.LastHandshake) <= OnlineWindow
}

// ValidDeviceName проверяет имя устройства: 1–32 символа, буквы/цифры/пробел/-_. (FR-3.8).
func ValidDeviceName(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return fmt.Errorf("имя устройства пустое")
	}
	if n := len([]rune(s)); n > 32 {
		return fmt.Errorf("имя устройства длиннее 32 символов (%d)", n)
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == ' ' || r == '-' || r == '_' || r == '.' {
			continue
		}
		return fmt.Errorf("недопустимый символ %q в имени устройства", r)
	}
	return nil
}

// CreateDevice сохраняет устройство. Ключи и адрес готовит вызывающий (hub): store следит за
// целостностью — лимит пользователя, уникальность имени, адреса и публичного ключа.
func (s *Store) CreateDevice(ctx context.Context, d Device) (int64, error) {
	d.Name = strings.TrimSpace(d.Name)
	if err := ValidDeviceName(d.Name); err != nil {
		return 0, err
	}
	if d.PublicKey == "" || d.Address == "" {
		return 0, fmt.Errorf("устройство без публичного ключа или адреса")
	}
	if d.Preset == "" {
		d.Preset = PresetPhone
	}
	if d.CreatedBy == "" {
		d.CreatedBy = "admin"
	}
	if d.Status == "" {
		d.Status = "active"
	}
	var max, used int
	if err := s.db.QueryRowContext(ctx, `SELECT max_devices FROM users WHERE id = ? AND deleted_at IS NULL`, d.UserID).Scan(&max); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, ErrNotFound
		}
		return 0, err
	}
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM devices WHERE user_id = ? AND deleted_at IS NULL`, d.UserID).Scan(&used); err != nil {
		return 0, err
	}
	if used >= max {
		return 0, fmt.Errorf("достигнут лимит устройств пользователя (%d)", max)
	}
	if err := s.nameTaken(ctx, `SELECT 1 FROM devices WHERE user_id = ? AND deleted_at IS NULL AND name_ci = ? AND id <> ?`,
		"у пользователя уже есть устройство с таким именем", d.UserID, strings.ToLower(d.Name), d.ID); err != nil {
		return 0, err
	}
	ov, _ := json.Marshal(d.Overrides)
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, `INSERT INTO devices (user_id, interface_id, name, name_ci, preset, private_key, public_key, preshared_key, address, overrides, status, created_by, note, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.UserID, d.InterfaceID, d.Name, strings.ToLower(d.Name), d.Preset, d.PrivateKey, d.PublicKey, d.PresharedKey, d.Address, string(ov), d.Status, d.CreatedBy, d.Note, now, now)
	if err != nil {
		return 0, friendlyConstraint(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	// Пир этого ключа мог уже наблюдаться на интерфейсе (импорт, ручная правка) — связываем.
	if _, err := s.db.ExecContext(ctx, `UPDATE peers SET device_id = ? WHERE interface_id = ? AND public_key = ?`, id, d.InterfaceID, d.PublicKey); err != nil {
		return 0, err
	}
	return id, nil
}

// UpdateDevice сохраняет редактируемые поля (имя, пресет, переопределения, заметка, владелец).
func (s *Store) UpdateDevice(ctx context.Context, d Device) error {
	d.Name = strings.TrimSpace(d.Name)
	if err := ValidDeviceName(d.Name); err != nil {
		return err
	}
	if err := s.nameTaken(ctx, `SELECT 1 FROM devices WHERE user_id = ? AND deleted_at IS NULL AND name_ci = ? AND id <> ?`,
		"у пользователя уже есть устройство с таким именем", d.UserID, strings.ToLower(d.Name), d.ID); err != nil {
		return err
	}
	ov, _ := json.Marshal(d.Overrides)
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET name = ?, name_ci = ?, preset = ?, overrides = ?, note = ?, user_id = ?, updated_at = ?
		WHERE id = ? AND deleted_at IS NULL`, d.Name, strings.ToLower(d.Name), d.Preset, string(ov), d.Note, d.UserID, time.Now().Unix(), d.ID)
	if err != nil {
		return friendlyConstraint(err)
	}
	return affected(res, nil)
}

// SetDeviceStatus включает/выключает устройство (FR-3.3). Снятие пира — забота вызывающего.
func (s *Store) SetDeviceStatus(ctx context.Context, id int64, status string) error {
	if status != "active" && status != "disabled" {
		return fmt.Errorf("статус устройства: ожидается active|disabled, получено %q", status)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET status = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`, status, time.Now().Unix(), id)
	return affected(res, err)
}

// RotateKeys записывает новую пару ключей устройства, сохраняя адрес (FR-3.5).
func (s *Store) RotateKeys(ctx context.Context, id int64, priv, pub, psk string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET private_key = ?, public_key = ?, preshared_key = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`,
		priv, pub, psk, time.Now().Unix(), id)
	if err != nil {
		return friendlyConstraint(err)
	}
	if err := affected(res, nil); err != nil {
		return err
	}
	// Старый пир этого устройства больше не его: связь снимаем, новый ключ свяжется при следующем обходе.
	_, err = s.db.ExecContext(ctx, `UPDATE peers SET device_id = NULL WHERE device_id = ? AND public_key <> ?`, id, pub)
	return err
}

// DeleteDevice — мягкое удаление (FR-3.4).
func (s *Store) DeleteDevice(ctx context.Context, id int64) error {
	now := time.Now().Unix()
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET status = 'deleted', deleted_at = ?, updated_at = ? WHERE id = ? AND deleted_at IS NULL`, now, now, id)
	return affected(res, err)
}

// RestoreDevice возвращает устройство из корзины выключенным.
func (s *Store) RestoreDevice(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE devices SET status = 'disabled', deleted_at = NULL, updated_at = ? WHERE id = ? AND deleted_at IS NOT NULL`, time.Now().Unix(), id)
	if err != nil {
		return friendlyConstraint(err)
	}
	return affected(res, nil)
}

// MarkIssued отмечает выдачу конфига (в аудит пишется отдельно, FR-4.6).
func (s *Store) MarkIssued(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE devices SET issued_at = ?, issue_count = issue_count + 1 WHERE id = ?`, time.Now().Unix(), id)
	return err
}

// deviceColumns — колонки выборки устройства. Трафик за сутки добирается отдельно (fillDeviceTraffic):
// подзапрос к traffic_raw на каждую строку превращал список из 600 устройств в секунды ожидания.
const deviceColumns = `d.id, d.user_id, d.interface_id, d.name, d.preset, d.private_key, d.public_key, d.preshared_key, d.address, d.overrides,
		d.status, d.created_by, d.note, d.created_at, d.updated_at, COALESCE(d.deleted_at,0), COALESCE(d.issued_at,0), d.issue_count,
		COALESCE(u.name,''), COALESCE(i.name,''),
		COALESCE(p.id,0), COALESCE(p.removed_at,0), COALESCE(st.last_handshake,0), COALESCE(st.endpoint,''), COALESCE(st.rx_total,0), COALESCE(st.tx_total,0)`

const deviceJoins = ` FROM devices d
		LEFT JOIN users u ON u.id = d.user_id
		LEFT JOIN interfaces i ON i.id = d.interface_id
		LEFT JOIN peers p ON p.device_id = d.id
		LEFT JOIN peer_state st ON st.peer_id = p.id`

func scanDevice(r scanner) (Device, error) {
	var d Device
	var ov string
	var created, updated, deleted, issued, removed, hs int64
	err := r.Scan(&d.ID, &d.UserID, &d.InterfaceID, &d.Name, &d.Preset, &d.PrivateKey, &d.PublicKey, &d.PresharedKey, &d.Address, &ov,
		&d.Status, &d.CreatedBy, &d.Note, &created, &updated, &deleted, &issued, &d.IssueCount,
		&d.UserName, &d.InterfaceName, &d.PeerID, &removed, &hs, &d.Endpoint, &d.RxTotal, &d.TxTotal)
	if err != nil {
		return Device{}, err
	}
	json.Unmarshal([]byte(ov), &d.Overrides)
	d.CreatedAt, d.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	d.DeletedAt, d.IssuedAt, d.LastHandshake = fromUnix(deleted), fromUnix(issued), fromUnix(hs)
	d.OnInterface = d.PeerID != 0 && removed == 0
	return d, nil
}

func (s *Store) devicesWhere(ctx context.Context, cond string, args ...any) ([]Device, error) {
	q := `SELECT ` + deviceColumns + deviceJoins + ` WHERE ` + cond + ` ORDER BY d.name_ci`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	var out []Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, s.fillDeviceTraffic(ctx, out)
}

// fillDeviceTraffic проставляет трафик за сутки всем устройствам выборки одним запросом.
func (s *Store) fillDeviceTraffic(ctx context.Context, devices []Device) error {
	byPeer := make(map[int64]*Device, len(devices))
	ids := make([]any, 0, len(devices))
	for i := range devices {
		if devices[i].PeerID == 0 {
			continue
		}
		byPeer[devices[i].PeerID] = &devices[i]
		ids = append(ids, devices[i].PeerID)
	}
	if len(ids) == 0 {
		return nil
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	rows, err := s.db.QueryContext(ctx, `SELECT peer_id, COALESCE(SUM(rx),0), COALESCE(SUM(tx),0) FROM traffic_raw
		WHERE ts >= ? AND peer_id IN (`+ph+`) GROUP BY peer_id`, append([]any{time.Now().Unix() - 86400}, ids...)...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var peer int64
		var rx, tx uint64
		if err := rows.Scan(&peer, &rx, &tx); err != nil {
			return err
		}
		if d := byPeer[peer]; d != nil {
			d.Rx24, d.Tx24 = rx, tx
		}
	}
	return rows.Err()
}

// CountDevices — сколько устройств на интерфейсе: дашборду нужен счётчик, а не 600 карточек с ключами.
func (s *Store) CountDevices(ctx context.Context, ifaceID int64) (total, active int, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END),0)
		FROM devices WHERE interface_id = ? AND deleted_at IS NULL`, ifaceID).Scan(&total, &active)
	return total, active, err
}

// DeviceByID возвращает устройство вместе с секретами (для выдачи конфига).
func (s *Store) DeviceByID(ctx context.Context, id int64) (Device, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+deviceColumns+deviceJoins+` WHERE d.id = ?`, id)
	d, err := scanDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	if err != nil {
		return Device{}, err
	}
	one := []Device{d}
	if err := s.fillDeviceTraffic(ctx, one); err != nil {
		return Device{}, err
	}
	return one[0], nil
}

// DeviceByPublicKey ищет устройство интерфейса по публичному ключу (импорт идемпотентен, FR-11.3).
func (s *Store) DeviceByPublicKey(ctx context.Context, ifaceID int64, pub string) (Device, error) {
	row := s.db.QueryRowContext(ctx, `SELECT `+deviceColumns+deviceJoins+` WHERE d.interface_id = ? AND d.public_key = ? AND d.deleted_at IS NULL`, ifaceID, pub)
	d, err := scanDevice(row)
	if errors.Is(err, sql.ErrNoRows) {
		return Device{}, ErrNotFound
	}
	return d, err
}

// DevicesByUser — устройства пользователя (без корзины).
func (s *Store) DevicesByUser(ctx context.Context, userID int64) ([]Device, error) {
	return s.devicesWhere(ctx, `d.user_id = ? AND d.deleted_at IS NULL`, userID)
}

// DefaultDeviceName — имя нового устройства, когда человек ничего не вписал: «Устройство N» по
// числу уже заведённых. Форма показывает это же имя серым placeholder'ом, поэтому счёт идёт по
// живым устройствам (корзина имён не занимает); занятый номер пропускается — имя обязано быть
// уникальным у владельца, и отказ на ровном месте здесь никому не нужен.
func (s *Store) DefaultDeviceName(ctx context.Context, userID int64) (string, error) {
	list, err := s.DevicesByUser(ctx, userID)
	if err != nil {
		return "", err
	}
	taken := make(map[string]bool, len(list))
	for _, d := range list {
		taken[strings.ToLower(d.Name)] = true
	}
	for n := len(list) + 1; n <= len(list)+1000; n++ {
		cand := "Устройство " + strconv.Itoa(n)
		if !taken[strings.ToLower(cand)] {
			return cand, nil
		}
	}
	// Тысяча занятых подряд — придумывать дальше незачем: пусть уникальный индекс скажет своё.
	return "Устройство " + strconv.Itoa(len(list)+1), nil
}

// DevicesOfUsers — устройства сразу многих пользователей одной выборкой: список пользователей
// показывает их лейблами, и запрос на каждого превратил бы страницу в шестьдесят запросов.
func (s *Store) DevicesOfUsers(ctx context.Context, userIDs []int64) (map[int64][]Device, error) {
	out := map[int64][]Device{}
	if len(userIDs) == 0 {
		return out, nil
	}
	devices, err := s.devicesWhere(ctx, `d.user_id IN (`+placeholders(len(userIDs))+`) AND d.deleted_at IS NULL`,
		toArgs(userIDs)...)
	if err != nil {
		return nil, err
	}
	for _, d := range devices {
		out[d.UserID] = append(out[d.UserID], d)
	}
	return out, nil
}

// DevicesByInterface — устройства интерфейса (без корзины); onlyActive — только те, что должны стоять на интерфейсе.
func (s *Store) DevicesByInterface(ctx context.Context, ifaceID int64, onlyActive bool) ([]Device, error) {
	cond := `d.interface_id = ? AND d.deleted_at IS NULL`
	if onlyActive {
		cond += ` AND d.status = 'active' AND u.status = 'active' AND u.deleted_at IS NULL`
	}
	return s.devicesWhere(ctx, cond, ifaceID)
}

// DevicesByPeerIDs — устройства, стоящие за указанными пирами (события об активности приходят
// от пиров, а имя человеку нужно от устройства).
func (s *Store) DevicesByPeerIDs(ctx context.Context, peerIDs []int64) ([]Device, error) {
	if len(peerIDs) == 0 {
		return nil, nil
	}
	return s.devicesWhere(ctx, `d.deleted_at IS NULL AND d.id IN (SELECT device_id FROM peers WHERE id IN (`+placeholders(len(peerIDs))+`) AND device_id IS NOT NULL)`, toArgs(peerIDs)...)
}

// DevicesByIDs возвращает устройства по списку id: карточке интерфейса нужны только те,
// что сопоставлены пирам, а не все устройства сервера.
func (s *Store) DevicesByIDs(ctx context.Context, ids []int64) ([]Device, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	args := make([]any, 0, len(ids))
	for _, id := range ids {
		args = append(args, id)
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
	return s.devicesWhere(ctx, `d.id IN (`+ph+`)`, args...)
}

// DeletedDevices — корзина устройств (для восстановления в течение PurgeAfter).
func (s *Store) DeletedDevices(ctx context.Context) ([]Device, error) {
	return s.devicesWhere(ctx, `d.deleted_at IS NOT NULL`)
}

// ---------- адресация ----------

// NextAddress выдаёт наименьший свободный адрес подсети интерфейса.
// Заняты: адрес сервера, адреса устройств (включая корзину — до окончательной очистки)
// и адреса пиров интерфейса, ещё не сопоставленных устройствам.
func (s *Store) NextAddress(ctx context.Context, iface Interface) (string, error) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(iface.Subnet))
	if err != nil {
		return "", fmt.Errorf("подсеть интерфейса %q: %w", iface.Subnet, err)
	}
	if !prefix.Addr().Is4() {
		return "", fmt.Errorf("подсеть %s: поддерживается только IPv4", iface.Subnet)
	}
	taken := map[netip.Addr]bool{}
	if a, ok := addrOf(iface.ServerAddress); ok {
		taken[a] = true
	}
	rows, err := s.db.QueryContext(ctx, `SELECT address FROM devices WHERE interface_id = ?`, iface.ID)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			rows.Close()
			return "", err
		}
		if a, ok := addrOf(s); ok {
			taken[a] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", err
	}
	prows, err := s.db.QueryContext(ctx, `SELECT allowed_ips FROM peers WHERE interface_id = ? AND removed_at IS NULL AND device_id IS NULL`, iface.ID)
	if err != nil {
		return "", err
	}
	for prows.Next() {
		var allowed string
		if err := prows.Scan(&allowed); err != nil {
			prows.Close()
			return "", err
		}
		for _, part := range strings.Split(allowed, ",") {
			if a, ok := addrOf(part); ok {
				taken[a] = true
			}
		}
	}
	prows.Close()
	if err := prows.Err(); err != nil {
		return "", err
	}
	network := prefix.Masked()
	last := lastAddr(network)
	for a := network.Addr().Next(); a.IsValid() && a.Compare(last) < 0; a = a.Next() {
		if !taken[a] {
			return a.String(), nil
		}
	}
	return "", fmt.Errorf("в подсети %s нет свободных адресов", prefix)
}

// addrOf вытаскивает адрес из строки вида "10.20.0.5", "10.20.0.5/32", " 10.20.0.5/16 ".
func addrOf(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, false
	}
	if host, _, ok := strings.Cut(s, "/"); ok {
		s = host
	}
	a, err := netip.ParseAddr(s)
	if err != nil || !a.Is4() {
		return netip.Addr{}, false
	}
	return a, true
}

// lastAddr — широковещательный адрес префикса (верхняя граница диапазона).
func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().As4()
	host := 32 - p.Bits()
	for i := 0; i < host; i++ {
		b[3-i/8] |= 1 << (i % 8)
	}
	return netip.AddrFrom4(b)
}

// nameTaken возвращает ошибку msg, если запрос q находит хотя бы одну строку.
// Уникальность имён проверяется здесь, а не индексом: SQLite не знает регистра кириллицы,
// а индекс по пользовательской функции сделал бы файл БД нечитаемым обычным sqlite3.
func (s *Store) nameTaken(ctx context.Context, q, msg string, args ...any) error {
	var one int
	err := s.db.QueryRowContext(ctx, q, args...).Scan(&one)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return nil
	case err != nil:
		return err
	}
	return errors.New(msg)
}

// friendlyConstraint переводит нарушения уникальности в понятные сообщения.
func friendlyConstraint(err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	switch {
	case strings.Contains(s, "devices_name"):
		return fmt.Errorf("у пользователя уже есть устройство с таким именем")
	case strings.Contains(s, "devices_addr"):
		return fmt.Errorf("адрес уже занят другим устройством этого интерфейса")
	case strings.Contains(s, "devices_pub"):
		return fmt.Errorf("устройство с таким публичным ключом уже есть на интерфейсе")
	case strings.Contains(s, "users_name"):
		return fmt.Errorf("пользователь с таким именем уже есть")
	}
	return err
}

// TrafficSince — сумма трафика по пирам за период. Для суток берётся сырой ряд, для месяца —
// часовые агрегаты: месяц по сырым записям — это миллионы строк, а точность до часа тут не нужна.
func (s *Store) TrafficSince(ctx context.Context, peerIDs []int64, since time.Time) (map[int64][2]uint64, error) {
	out := map[int64][2]uint64{}
	if len(peerIDs) == 0 {
		return out, nil
	}
	table, col := "traffic_raw", "ts"
	if time.Since(since) > 24*time.Hour {
		table, col = "traffic_1h", "bucket"
	}
	args := make([]any, 0, len(peerIDs)+1)
	for _, id := range peerIDs {
		args = append(args, id)
	}
	ph := strings.TrimSuffix(strings.Repeat("?,", len(peerIDs)), ",")
	args = append(args, since.Unix())
	rows, err := s.db.QueryContext(ctx, `SELECT peer_id, COALESCE(SUM(rx),0), COALESCE(SUM(tx),0) FROM `+table+`
		WHERE peer_id IN (`+ph+`) AND `+col+` >= ? GROUP BY peer_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var rx, tx uint64
		if err := rows.Scan(&id, &rx, &tx); err != nil {
			return nil, err
		}
		out[id] = [2]uint64{rx, tx}
	}
	return out, rows.Err()
}
