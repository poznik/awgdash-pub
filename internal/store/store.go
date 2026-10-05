// Package store — SQLite-хранилище хаба (modernc.org/sqlite, без cgo): миграции, запросы, агрегаты, ретеншн.
package store

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

// OnlineWindow — хендшейк не старше этого = устройство онлайн (SPEC FR-6.2).
const OnlineWindow = 180 * time.Second

// Store — соединение с БД. Методы безопасны для конкурентного вызова (sqlite + WAL).
type Store struct {
	db *sql.DB
}

// Open открывает (создаёт) БД и применяет миграции.
func Open(path string) (*Store, error) {
	// busy_timeout — 15 с: рядом с сервисом работают разовые команды CLI, и ждать чужую
	// запись правильнее, чем падать с SQLITE_BUSY. txlock=immediate берёт запись сразу,
	// не апгрейдя транзакцию с чтения (иначе два писателя ловят deadlock).
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=busy_timeout(15000)&_pragma=foreign_keys(ON)&_pragma=synchronous(NORMAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1) // один писатель; чтения через WAL не блокируются писателем
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.fillNameCI(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close закрывает соединение.
func (s *Store) Close() error { return s.db.Close() }

// DB — сырое соединение для редких запросов вне пакета (CLI, тесты).
func (s *Store) DB() *sql.DB { return s.db }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	entries, err := fs.ReadDir(migrations, "migrations")
	if err != nil {
		return err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	for _, n := range names {
		var done int
		if err := s.db.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, n).Scan(&done); err != nil {
			return err
		}
		if done > 0 {
			continue
		}
		body, err := migrations.ReadFile("migrations/" + n)
		if err != nil {
			return err
		}
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(body)); err != nil {
			tx.Rollback()
			return fmt.Errorf("миграция %s: %w", n, err)
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)`, n, time.Now().Unix()); err != nil {
			tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// fillNameCI проставляет имена в нижнем регистре там, где колонка пуста: миграция этого не умеет —
// SQLite не опускает регистр кириллицы, это делает Go.
func (s *Store) fillNameCI() error {
	type row struct {
		id   int64
		name string
	}
	for _, table := range []string{"users", "devices"} {
		rows, err := s.db.Query(`SELECT id, name FROM ` + table + ` WHERE name_ci = ''`)
		if err != nil {
			return err
		}
		var list []row
		for rows.Next() {
			var r row
			if err := rows.Scan(&r.id, &r.name); err != nil {
				rows.Close()
				return err
			}
			list = append(list, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, r := range list {
			if _, err := s.db.Exec(`UPDATE `+table+` SET name_ci = ? WHERE id = ?`, strings.ToLower(r.name), r.id); err != nil {
				return err
			}
		}
	}
	return nil
}

// ---------- серверы ----------

// Server — строка таблицы servers.
type Server struct {
	ID             int64
	Slug, Title    string
	Transport      string
	PublicIP       string
	EgressIface    string
	Kernel         string
	AWGVersion     string
	AwgdashVersion string
	RebootRequired bool
	LastSeenAt     time.Time
	// Как хаб добирается до узла: 'local' — тот же процесс, 'ssh' — туннель до другой машины.
	SSHHost    string
	SSHKeyPath string
	NodePort   int
	Enabled    bool
	Note       string
	// Country — код страны (ISO 3166-1 alpha-2) для флага рядом с названием.
	Country string
	// RetiredAt — сервер выведен из парка: машины больше нет (SPEC FR-10.6). Ноль — в парке.
	RetiredAt time.Time
}

// Retired — сервер выведен из парка.
func (v Server) Retired() bool { return !v.RetiredAt.IsZero() }

// Flag — флаг страны сервера эмодзи. Пустой код даёт пустую строку: лучше без флага,
// чем чужой.
func (s Server) Flag() string { return CountryFlag(s.CountryOrGuess()) }

// CountryOrGuess — заданный код страны или догадка по слагу: слаги парка исторически
// совпадают с кодами стран (de, ru).
func (s Server) CountryOrGuess() string {
	if len(s.Country) == 2 {
		return strings.ToUpper(s.Country)
	}
	if len(s.Slug) == 2 {
		return strings.ToUpper(s.Slug)
	}
	return ""
}

// CountryFlag превращает двухбуквенный код в эмодзи-флаг (пара regional indicator).
func CountryFlag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return ""
	}
	const base = 0x1F1E6 // 🇦
	return string(rune(base+int(code[0]-'A'))) + string(rune(base+int(code[1]-'A')))
}

// Local — узел живёт в этом же процессе.
func (s Server) Local() bool { return s.Transport == "local" }

// UpsertLocalServer регистрирует локальный узел (хаб = узел) и возвращает его id.
func (s *Store) UpsertLocalServer(ctx context.Context, slug, title string) (int64, error) {
	// Имя, заданное человеком (`awgdash server set --title`), при старте не затирается:
	// иначе панель на каждом перезапуске возвращала бы слаг из конфига.
	_, err := s.db.ExecContext(ctx, `INSERT INTO servers (slug, title, transport) VALUES (?, ?, 'local')
		ON CONFLICT(slug) DO UPDATE SET title = CASE
			WHEN servers.title = '' OR servers.title = servers.slug THEN excluded.title
			ELSE servers.title END`, slug, title)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.db.QueryRowContext(ctx, `SELECT id FROM servers WHERE slug = ?`, slug).Scan(&id)
	return id, err
}

// TouchServer обновляет факты о машине и отметку «виден».
func (s *Store) TouchServer(ctx context.Context, id int64, publicIP, egress, kernel, awgVersion, awgdashVersion string, reboot bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE servers SET public_ip = ?, egress_iface = ?, kernel = ?, awg_version = ?, awgdash_version = ?, reboot_required = ?, last_seen_at = ? WHERE id = ?`,
		publicIP, egress, kernel, awgVersion, awgdashVersion, b2i(reboot), time.Now().Unix(), id)
	return err
}

// Servers возвращает все серверы.
func (s *Store) Servers(ctx context.Context) ([]Server, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, slug, title, transport, COALESCE(public_ip,''), COALESCE(egress_iface,''),
		COALESCE(kernel,''), COALESCE(awg_version,''), COALESCE(awgdash_version,''), reboot_required, COALESCE(last_seen_at,0),
		COALESCE(ssh_host,''), COALESCE(ssh_key_path,''), COALESCE(node_port,0), enabled, note, country,
		COALESCE(retired_at,0) FROM servers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Server
	for rows.Next() {
		var v Server
		var rb, enabled int
		var seen, retired int64
		if err := rows.Scan(&v.ID, &v.Slug, &v.Title, &v.Transport, &v.PublicIP, &v.EgressIface, &v.Kernel, &v.AWGVersion,
			&v.AwgdashVersion, &rb, &seen, &v.SSHHost, &v.SSHKeyPath, &v.NodePort, &enabled, &v.Note, &v.Country, &retired); err != nil {
			return nil, err
		}
		v.RebootRequired, v.Enabled = rb == 1, enabled == 1
		if seen > 0 {
			v.LastSeenAt = time.Unix(seen, 0)
		}
		if retired > 0 {
			v.RetiredAt = time.Unix(retired, 0)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---------- интерфейсы ----------

// Interface — строка таблицы interfaces.
type Interface struct {
	ID                int64
	ServerID          int64
	Name              string
	Stack, Mode       string
	ConfPath          string
	Subnet            string
	ServerAddress     string
	ListenPort        int
	MTU               int
	Endpoints         []Endpoint
	ServerPublicKey   string
	Obfuscation       map[string]string
	IsAWG             bool
	DefaultDNS        string
	DefaultKeepalive  int
	DefaultAllowedIPs string
	PSKEnabled        bool
	SaveConfig        bool
	UnitActive        bool
	Status            string
	ConfMtime         time.Time
	LastSeenAt        time.Time
	LastVerifiedAt    time.Time
	LastVerifyOK      *bool
	LastVerify        json.RawMessage
}

// Endpoint — вариант endpoint для клиентских конфигов (FR-1.7).
type Endpoint struct {
	Label   string `json:"label"`
	Host    string `json:"host"`
	Port    int    `json:"port"`
	Primary bool   `json:"primary"`
}

// InterfaceFacts — то, что узел наблюдает и хаб записывает при каждом обходе.
type InterfaceFacts struct {
	ConfPath        string
	Subnet          string
	ServerAddress   string
	ListenPort      int
	MTU             int
	ServerPublicKey string
	Obfuscation     map[string]string
	IsAWG           bool
	SaveConfig      bool
	UnitActive      bool
	ConfMtime       time.Time
}

// UpsertInterface создаёт интерфейс в режиме observe или обновляет наблюдаемые факты. Возвращает id.
func (s *Store) UpsertInterface(ctx context.Context, serverID int64, name string, f InterfaceFacts) (int64, error) {
	obf, _ := json.Marshal(f.Obfuscation)
	now := time.Now().Unix()
	_, err := s.db.ExecContext(ctx, `INSERT INTO interfaces (server_id, name, conf_path, subnet, server_address, listen_port, mtu, server_public_key, obfuscation, is_awg, save_config, unit_active, conf_mtime, last_seen_at, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ok')
		ON CONFLICT(server_id, name) DO UPDATE SET conf_path = excluded.conf_path, subnet = excluded.subnet, server_address = excluded.server_address,
		  listen_port = excluded.listen_port, mtu = excluded.mtu, server_public_key = excluded.server_public_key, obfuscation = excluded.obfuscation,
		  is_awg = excluded.is_awg, save_config = excluded.save_config, unit_active = excluded.unit_active, conf_mtime = excluded.conf_mtime, last_seen_at = excluded.last_seen_at, status = 'ok'`,
		serverID, name, f.ConfPath, f.Subnet, f.ServerAddress, f.ListenPort, f.MTU, f.ServerPublicKey, string(obf), b2i(f.IsAWG), b2i(f.SaveConfig), b2i(f.UnitActive), f.ConfMtime.Unix(), now)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.db.QueryRowContext(ctx, `SELECT id FROM interfaces WHERE server_id = ? AND name = ?`, serverID, name).Scan(&id)
	return id, err
}

// StatusGone — интерфейса больше нет на сервере: обход его не нашёл. Запись остаётся (на ней
// висят устройства и история), а убирает её человек — панель молча не удаляет (FR-1.9).
const StatusGone = "gone"

// MarkGoneInterfaces помечает интерфейсы сервера, которых не было в последнем обходе, и
// возвращает имена тех, кто пропал именно сейчас: сказать об этом нужно один раз. Вернувшийся
// интерфейс выходит из этого состояния сам — UpsertInterface пишет статус 'ok'.
func (s *Store) MarkGoneInterfaces(ctx context.Context, serverID int64, present []string) ([]string, error) {
	q := `SELECT id, name FROM interfaces WHERE server_id = ? AND status <> ?`
	args := []any{serverID, StatusGone}
	if len(present) > 0 {
		q += ` AND name NOT IN (?` + strings.Repeat(`, ?`, len(present)-1) + `)`
		for _, n := range present {
			args = append(args, n)
		}
	}
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	type gone struct {
		id   int64
		name string
	}
	var list []gone
	for rows.Next() {
		var g gone
		if err := rows.Scan(&g.id, &g.name); err != nil {
			rows.Close()
			return nil, err
		}
		list = append(list, g)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(list))
	for _, g := range list {
		if _, err := s.db.ExecContext(ctx, `UPDATE interfaces SET status = ?, unit_active = 0 WHERE id = ?`, StatusGone, g.id); err != nil {
			return names, err
		}
		names = append(names, g.name)
	}
	return names, nil
}

// InterfaceBelongings — что уйдёт вместе с интерфейсом; показывается до подтверждения.
func (s *Store) InterfaceBelongings(ctx context.Context, id int64) (ServerBelongings, error) {
	var b ServerBelongings
	err := s.db.QueryRowContext(ctx, `SELECT 1,
		(SELECT COUNT(*) FROM peers WHERE interface_id = ?),
		(SELECT COUNT(*) FROM devices WHERE interface_id = ? AND deleted_at IS NULL),
		(SELECT COUNT(DISTINCT user_id) FROM devices WHERE interface_id = ? AND deleted_at IS NULL)`,
		id, id, id).Scan(&b.Interfaces, &b.Peers, &b.Devices, &b.Users)
	return b, err
}

// DeleteInterface убирает интерфейс из панели вместе с его пирами, устройствами и историей.
// Зовётся, когда интерфейса больше нет на сервере: держать его записи незачем, а устройства на
// нём всё равно не подключатся (FR-1.9).
func (s *Store) DeleteInterface(ctx context.Context, id int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM traffic_raw WHERE peer_id IN (SELECT id FROM peers WHERE interface_id = ?)`,
		`DELETE FROM traffic_5m WHERE peer_id IN (SELECT id FROM peers WHERE interface_id = ?)`,
		`DELETE FROM traffic_1h WHERE peer_id IN (SELECT id FROM peers WHERE interface_id = ?)`,
		`DELETE FROM peer_state WHERE peer_id IN (SELECT id FROM peers WHERE interface_id = ?)`,
		`DELETE FROM peers WHERE interface_id = ?`,
		`DELETE FROM devices WHERE interface_id = ?`,
		`UPDATE users SET default_interface_id = NULL WHERE default_interface_id = ?`,
		`DELETE FROM interfaces WHERE id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	// Список разрешённых серверов хранится строкой «1,2,4»: удалённый интерфейс нужно вычистить
	// из неё, иначе он останется в правах у людей числом, за которым ничего нет.
	rows, err := tx.QueryContext(ctx, `SELECT id, allowed_interfaces FROM users WHERE allowed_interfaces <> ''`)
	if err != nil {
		return err
	}
	type row struct {
		id      int64
		allowed string
	}
	var users []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.allowed); err != nil {
			rows.Close()
			return err
		}
		users = append(users, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, u := range users {
		kept := make([]int64, 0, 4)
		for _, v := range parseIDs(u.allowed) {
			if v != id {
				kept = append(kept, v)
			}
		}
		if len(kept) == len(parseIDs(u.allowed)) {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE users SET allowed_interfaces = ? WHERE id = ?`, formatIDs(kept), u.id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// SetInterfaceStatus помечает интерфейс (например 'missing', когда конфиг исчез или дамп не читается).
func (s *Store) SetInterfaceStatus(ctx context.Context, id int64, status string, unitActive bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE interfaces SET status = ?, unit_active = ? WHERE id = ?`, status, b2i(unitActive), id)
	return err
}

// SetEndpoints сохраняет варианты endpoint интерфейса (FR-1.7). Первый Primary становится
// основным; если такого нет, основным делается первый в списке.
func (s *Store) SetEndpoints(ctx context.Context, id int64, eps []Endpoint) error {
	seen := map[string]bool{}
	out := make([]Endpoint, 0, len(eps))
	primary := false
	for _, e := range eps {
		e.Label, e.Host = strings.TrimSpace(e.Label), strings.TrimSpace(e.Host)
		if e.Host == "" || e.Port <= 0 || e.Port > 65535 {
			continue
		}
		if e.Label == "" {
			e.Label = e.Host
		}
		if seen[e.Label] {
			return fmt.Errorf("вариант %q повторяется — метки должны различаться", e.Label)
		}
		seen[e.Label] = true
		if e.Primary && !primary {
			primary = true
		} else {
			e.Primary = false
		}
		out = append(out, e)
	}
	if len(out) > 0 && !primary {
		out[0].Primary = true
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `UPDATE interfaces SET endpoints = ? WHERE id = ?`, string(b), id)
	return affected(res, err)
}

// SetInterfaceDefaults задаёт умолчания, из которых собирается клиентский конфиг: DNS, keepalive
// и AllowedIPs. Зовут её двое: импорт чужой панели, которая обязана выдавать ровно то, что было у
// людей до переезда (FR-11.4), и форма интерфейса в админке (FR-1.8) — интерфейсу, поднятому с
// нуля, умолчания взять больше неоткуда. Три поля пишутся разом: порознь они не читаются.
func (s *Store) SetInterfaceDefaults(ctx context.Context, id int64, dns string, keepalive int, allowedIPs string) error {
	dns, allowedIPs = NormalizeList(dns), NormalizeList(allowedIPs)
	if allowedIPs == "" {
		return fmt.Errorf("умолчание AllowedIPs пустое — конфиг без маршрутов бесполезен")
	}
	if keepalive < 0 || keepalive > 65535 {
		return fmt.Errorf("keepalive %d вне диапазона 0..65535", keepalive)
	}
	// DNS клиенты AmneziaWG принимают адресами; имя резолвера в этой строке молча не заработает,
	// а увидит это человек уже на своём устройстве. Пустая строка — законная: тогда строки DNS
	// в конфиге не будет вовсе (FR-4.1).
	for _, v := range strings.Split(dns, ", ") {
		if v == "" {
			continue
		}
		if _, err := netip.ParseAddr(v); err != nil {
			return fmt.Errorf("умолчание DNS: %q — не IP-адрес", v)
		}
	}
	res, err := s.db.ExecContext(ctx, `UPDATE interfaces SET default_dns = ?, default_keepalive = ?, default_allowed_ips = ? WHERE id = ?`,
		dns, keepalive, allowedIPs, id)
	return affected(res, err)
}

// SetInterfaceMode переключает режим интерфейса: observe (только наблюдение) или own (панель владеет
// пирами). Предпроверки — на стороне хаба (FR-1.2).
func (s *Store) SetInterfaceMode(ctx context.Context, id int64, mode string) error {
	if mode != "observe" && mode != "own" {
		return fmt.Errorf("режим интерфейса: ожидается observe|own, получено %q", mode)
	}
	res, err := s.db.ExecContext(ctx, `UPDATE interfaces SET mode = ? WHERE id = ?`, mode, id)
	return affected(res, err)
}

// SetVerify записывает результат сверки обфускации.
func (s *Store) SetVerify(ctx context.Context, id int64, ok bool, result any) error {
	b, _ := json.Marshal(result)
	_, err := s.db.ExecContext(ctx, `UPDATE interfaces SET last_verified_at = ?, last_verify_ok = ?, last_verify = ? WHERE id = ?`, time.Now().Unix(), b2i(ok), string(b), id)
	return err
}

// Interfaces возвращает интерфейсы сервера (serverID = 0 — все).
func (s *Store) Interfaces(ctx context.Context, serverID int64) ([]Interface, error) {
	q := `SELECT id, server_id, name, stack, mode, conf_path, subnet, server_address, listen_port, mtu, endpoints, server_public_key, obfuscation, is_awg,
		default_dns, default_keepalive, default_allowed_ips, psk_enabled, save_config, unit_active, status, COALESCE(conf_mtime,0), COALESCE(last_seen_at,0), COALESCE(last_verified_at,0), last_verify_ok, last_verify FROM interfaces`
	args := []any{}
	if serverID > 0 {
		q += ` WHERE server_id = ?`
		args = append(args, serverID)
	}
	q += ` ORDER BY server_id, name`
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Interface
	for rows.Next() {
		var v Interface
		var eps, obf, lv string
		var isAWG, psk, sc, ua int
		var mtime, seen, verAt int64
		var verOK sql.NullInt64
		if err := rows.Scan(&v.ID, &v.ServerID, &v.Name, &v.Stack, &v.Mode, &v.ConfPath, &v.Subnet, &v.ServerAddress, &v.ListenPort, &v.MTU, &eps, &v.ServerPublicKey, &obf, &isAWG,
			&v.DefaultDNS, &v.DefaultKeepalive, &v.DefaultAllowedIPs, &psk, &sc, &ua, &v.Status, &mtime, &seen, &verAt, &verOK, &lv); err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(eps), &v.Endpoints)
		json.Unmarshal([]byte(obf), &v.Obfuscation)
		v.IsAWG, v.PSKEnabled, v.SaveConfig, v.UnitActive = isAWG == 1, psk == 1, sc == 1, ua == 1
		if mtime > 0 {
			v.ConfMtime = time.Unix(mtime, 0)
		}
		if seen > 0 {
			v.LastSeenAt = time.Unix(seen, 0)
		}
		if verAt > 0 {
			v.LastVerifiedAt = time.Unix(verAt, 0)
		}
		if verOK.Valid {
			ok := verOK.Int64 == 1
			v.LastVerifyOK = &ok
		}
		v.LastVerify = json.RawMessage(lv)
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---------- пиры и статистика ----------

// PeerSample — наблюдение одного пира из дампа.
type PeerSample struct {
	PublicKey     string
	AllowedIPs    string
	HasPSK        bool
	InConf        bool
	Endpoint      string
	LastHandshake time.Time
	Rx, Tx        uint64
}

// SampleResult — итог записи одной выборки.
type SampleResult struct {
	Peers    int
	Online   int
	NewPeers int
	Rows     int // записей traffic_raw
	Resets   int
	// FirstOnline — пиры, у которых хендшейк случился впервые за всё наблюдение: панель
	// сообщает об этом администратору (FR-8.2). Пиры, впервые увиденные вместе с готовым
	// хендшейком (импорт), сюда не попадают — это не первое подключение, а первая встреча.
	FirstOnline []int64
}

// ApplySample записывает выборку пиров интерфейса: upsert пиров, дельты с детекцией сброса, состояние.
// Пиры, не попавшие в выборку, помечаются removed_at (при появлении снова — сбрасывается).
func (s *Store) ApplySample(ctx context.Context, ifaceID int64, at time.Time, samples []PeerSample, onlineThreshold time.Duration) (SampleResult, error) {
	var res SampleResult
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return res, err
	}
	defer tx.Rollback()
	now := at.Unix()
	seen := make([]int64, 0, len(samples))
	for _, p := range samples {
		res.Peers++
		var id int64
		var removed sql.NullInt64
		err := tx.QueryRowContext(ctx, `SELECT id, removed_at FROM peers WHERE interface_id = ? AND public_key = ?`, ifaceID, p.PublicKey).Scan(&id, &removed)
		switch {
		case err == sql.ErrNoRows:
			r, err := tx.ExecContext(ctx, `INSERT INTO peers (interface_id, public_key, allowed_ips, has_psk, in_conf, first_seen_at, last_seen_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				ifaceID, p.PublicKey, p.AllowedIPs, b2i(p.HasPSK), b2i(p.InConf), now, now)
			if err != nil {
				return res, err
			}
			id, _ = r.LastInsertId()
			res.NewPeers++
		case err != nil:
			return res, err
		default:
			if _, err := tx.ExecContext(ctx, `UPDATE peers SET allowed_ips = ?, has_psk = ?, in_conf = ?, last_seen_at = ?, removed_at = NULL WHERE id = ?`, p.AllowedIPs, b2i(p.HasPSK), b2i(p.InConf), now, id); err != nil {
				return res, err
			}
		}
		seen = append(seen, id)
		var prevRx, prevTx, rxTotal, txTotal uint64
		var sampledAt int64
		var firstHS sql.NullInt64
		err = tx.QueryRowContext(ctx, `SELECT rx_counter, tx_counter, rx_total, tx_total, sampled_at, first_handshake_at FROM peer_state WHERE peer_id = ?`, id).Scan(&prevRx, &prevTx, &rxTotal, &txTotal, &sampledAt, &firstHS)
		var hs any
		if !p.LastHandshake.IsZero() {
			hs = p.LastHandshake.Unix()
		}
		hadFirst := firstHS.Valid
		if !firstHS.Valid && hs != nil {
			firstHS = sql.NullInt64{Int64: p.LastHandshake.Unix(), Valid: true}
		}
		if err == sql.ErrNoRows {
			// Первая выборка — база для дельт, трафик не начисляем.
			if _, err := tx.ExecContext(ctx, `INSERT INTO peer_state (peer_id, rx_counter, tx_counter, last_handshake, first_handshake_at, endpoint, sampled_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
				id, p.Rx, p.Tx, hs, nullInt(firstHS), p.Endpoint, now); err != nil {
				return res, err
			}
		} else if err != nil {
			return res, err
		} else {
			if !hadFirst && firstHS.Valid {
				res.FirstOnline = append(res.FirstOnline, id)
			}
			drx, dtx := p.Rx-prevRx, p.Tx-prevTx
			reset := 0
			if p.Rx < prevRx || p.Tx < prevTx {
				// Счётчики обнулились (рестарт интерфейса / пересоздание пира): считаем от нуля.
				drx, dtx = p.Rx, p.Tx
				reset = 1
				res.Resets++
			}
			if drx > 0 || dtx > 0 {
				if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO traffic_raw (ts, peer_id, rx, tx) VALUES (?, ?, ?, ?)`, now, id, drx, dtx); err != nil {
					return res, err
				}
				res.Rows++
			}
			if _, err := tx.ExecContext(ctx, `UPDATE peer_state SET rx_counter = ?, tx_counter = ?, last_handshake = ?, first_handshake_at = ?, endpoint = ?, sampled_at = ?, rx_total = rx_total + ?, tx_total = tx_total + ?, resets = resets + ? WHERE peer_id = ?`,
				p.Rx, p.Tx, hs, nullInt(firstHS), p.Endpoint, now, drx, dtx, reset, id); err != nil {
				return res, err
			}
		}
		if !p.LastHandshake.IsZero() && at.Sub(p.LastHandshake) <= onlineThreshold {
			res.Online++
		}
	}
	// Исчезнувшие пиры.
	q := `UPDATE peers SET removed_at = ? WHERE interface_id = ? AND removed_at IS NULL`
	args := []any{now, ifaceID}
	if len(seen) > 0 {
		ph := strings.TrimSuffix(strings.Repeat("?,", len(seen)), ",")
		q += ` AND id NOT IN (` + ph + `)`
		for _, id := range seen {
			args = append(args, id)
		}
	}
	if _, err := tx.ExecContext(ctx, q, args...); err != nil {
		return res, err
	}
	if _, err := tx.ExecContext(ctx, linkPeersSQL, ifaceID); err != nil {
		return res, err
	}
	return res, tx.Commit()
}

// linkPeersSQL связывает наблюдаемых пиров с устройствами по публичному ключу: пир мог появиться
// раньше устройства (импорт, ручная правка конфига) или наоборот. Параметр — id интерфейса.
const linkPeersSQL = `UPDATE peers SET device_id = (SELECT d.id FROM devices d
		WHERE d.interface_id = peers.interface_id AND d.public_key = peers.public_key AND d.deleted_at IS NULL)
	WHERE interface_id = ? AND device_id IS NULL
	  AND EXISTS (SELECT 1 FROM devices d WHERE d.interface_id = peers.interface_id AND d.public_key = peers.public_key AND d.deleted_at IS NULL)`

// LinkPeers привязывает пиров интерфейса к устройствам по ключу (после импорта или создания устройств).
func (s *Store) LinkPeers(ctx context.Context, ifaceID int64) (int64, error) {
	res, err := s.db.ExecContext(ctx, linkPeersSQL, ifaceID)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// PeerRow — пир с состоянием для отображения.
type PeerRow struct {
	ID             int64
	InterfaceID    int64
	PublicKey      string
	AllowedIPs     string
	HasPSK         bool
	InConf         bool
	DeviceID       sql.NullInt64
	FirstSeenAt    time.Time
	LastSeenAt     time.Time
	RemovedAt      time.Time
	RxCounter      uint64
	TxCounter      uint64
	RxTotal        uint64
	TxTotal        uint64
	LastHandshake  time.Time
	FirstHandshake time.Time
	Endpoint       string
	SampledAt      time.Time
	Rx24, Tx24     uint64
}

// Peers возвращает пиров интерфейса с состоянием и суммой за последние 24 ч.
// OrphanPeer — пир, за которым в панели никого нет: он стоит на интерфейсе, а чьё это
// устройство, панель не знает. Такие приходят из чужих панелей и от ручной правки конфига.
type OrphanPeer struct {
	PeerRow
	Interface   string
	ServerSlug  string
	ServerTitle string
	Country     string
}

// OrphanPeers — все ничьи пиры парка. Раньше их можно было найти только внутри каждого
// интерфейса по очереди; человеку нужен один список (FR-1.6).
func (s *Store) OrphanPeers(ctx context.Context) ([]OrphanPeer, error) {
	ifaces, err := s.Interfaces(ctx, 0)
	if err != nil {
		return nil, err
	}
	servers, err := s.Servers(ctx)
	if err != nil {
		return nil, err
	}
	byID := map[int64]Server{}
	for _, srv := range servers {
		byID[srv.ID] = srv
	}
	var out []OrphanPeer
	for _, i := range ifaces {
		peers, err := s.Peers(ctx, i.ID, false)
		if err != nil {
			return nil, err
		}
		srv := byID[i.ServerID]
		for _, p := range peers {
			if p.DeviceID.Valid && p.DeviceID.Int64 != 0 {
				continue
			}
			out = append(out, OrphanPeer{PeerRow: p, Interface: i.Name, ServerSlug: srv.Slug,
				ServerTitle: srv.Title, Country: srv.CountryOrGuess()})
		}
	}
	return out, nil
}

func (s *Store) Peers(ctx context.Context, ifaceID int64, includeRemoved bool) ([]PeerRow, error) {
	q := `SELECT p.id, p.interface_id, p.public_key, p.allowed_ips, p.has_psk, p.in_conf, p.device_id, p.first_seen_at, p.last_seen_at, COALESCE(p.removed_at,0),
		COALESCE(st.rx_counter,0), COALESCE(st.tx_counter,0), COALESCE(st.rx_total,0), COALESCE(st.tx_total,0), COALESCE(st.last_handshake,0), COALESCE(st.first_handshake_at,0), COALESCE(st.endpoint,''), COALESCE(st.sampled_at,0),
		COALESCE((SELECT SUM(rx) FROM traffic_raw t WHERE t.peer_id = p.id AND t.ts >= ?),0),
		COALESCE((SELECT SUM(tx) FROM traffic_raw t WHERE t.peer_id = p.id AND t.ts >= ?),0)
		FROM peers p LEFT JOIN peer_state st ON st.peer_id = p.id WHERE p.interface_id = ?`
	if !includeRemoved {
		q += ` AND p.removed_at IS NULL`
	}
	q += ` ORDER BY p.allowed_ips`
	// За сутки считаем по сырым записям: они хранятся 48 ч (SPEC FR-6.3), окно суток внутри.
	rawFrom := time.Now().Unix() - 86400
	rows, err := s.db.QueryContext(ctx, q, rawFrom, rawFrom, ifaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PeerRow
	for rows.Next() {
		var v PeerRow
		var psk, inConf int
		var first, last, removed, hs, fhs, sampled int64
		if err := rows.Scan(&v.ID, &v.InterfaceID, &v.PublicKey, &v.AllowedIPs, &psk, &inConf, &v.DeviceID, &first, &last, &removed, &v.RxCounter, &v.TxCounter, &v.RxTotal, &v.TxTotal, &hs, &fhs, &v.Endpoint, &sampled, &v.Rx24, &v.Tx24); err != nil {
			return nil, err
		}
		v.HasPSK, v.InConf = psk == 1, inConf == 1
		v.FirstSeenAt, v.LastSeenAt = time.Unix(first, 0), time.Unix(last, 0)
		if removed > 0 {
			v.RemovedAt = time.Unix(removed, 0)
		}
		if hs > 0 {
			v.LastHandshake = time.Unix(hs, 0)
		}
		if fhs > 0 {
			v.FirstHandshake = time.Unix(fhs, 0)
		}
		if sampled > 0 {
			v.SampledAt = time.Unix(sampled, 0)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ---------- агрегаты и ретеншн ----------

// Rollup пересчитывает traffic_5m из сырых за последние `window` и traffic_1h из 5-минутных.
func (s *Store) Rollup(ctx context.Context, window time.Duration) error {
	from := time.Now().Add(-window).Unix()
	from5 := from - from%300
	if _, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO traffic_5m (bucket, peer_id, rx, tx)
		SELECT ts - ts % 300, peer_id, SUM(rx), SUM(tx) FROM traffic_raw WHERE ts >= ? GROUP BY peer_id, ts - ts % 300`, from5); err != nil {
		return err
	}
	from1 := from - from%3600
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO traffic_1h (bucket, peer_id, rx, tx)
		SELECT bucket - bucket % 3600, peer_id, SUM(rx), SUM(tx) FROM traffic_5m WHERE bucket >= ? GROUP BY peer_id, bucket - bucket % 3600`, from1)
	return err
}

// Retention удаляет устаревшие сырые и 5-минутные записи и старые метрики хоста.
func (s *Store) Retention(ctx context.Context, raw, m5 time.Duration) error {
	now := time.Now()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM traffic_raw WHERE ts < ?`, now.Add(-raw).Unix()); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM traffic_5m WHERE bucket < ?`, now.Add(-m5).Unix()); err != nil {
		return err
	}
	// Метрики хоста: минутные — 24 ч, дальше прореживаем до одной записи в час на 90 дней.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM host_metrics WHERE ts < ? AND ts % 3600 >= 60`, now.Add(-24*time.Hour).Unix()); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM host_metrics WHERE ts < ?`, now.Add(-90*24*time.Hour).Unix())
	return err
}

// ---------- метрики хоста ----------

// HostMetric — строка host_metrics.
type HostMetric struct {
	ServerID                                   int64
	TS                                         time.Time
	CPU                                        float64
	MemUsed, MemTotal, SwapUsed, SwapTotal     uint64
	DiskUsed, DiskTotal                        uint64
	Load1                                      float64
	NetRxBps, NetTxBps, NetRxBytes, NetTxBytes uint64
	PeersOnline                                int
}

// InsertHostMetric записывает минутную метрику.
func (s *Store) InsertHostMetric(ctx context.Context, m HostMetric) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO host_metrics (server_id, ts, cpu, mem_used, mem_total, swap_used, swap_total, disk_used, disk_total, load1, net_rx_bps, net_tx_bps, net_rx_bytes, net_tx_bytes, peers_online)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		m.ServerID, m.TS.Unix(), m.CPU, m.MemUsed, m.MemTotal, m.SwapUsed, m.SwapTotal, m.DiskUsed, m.DiskTotal, m.Load1, m.NetRxBps, m.NetTxBps, m.NetRxBytes, m.NetTxBytes, m.PeersOnline)
	return err
}

// HostMetrics возвращает метрики сервера за период (по возрастанию времени).
func (s *Store) HostMetrics(ctx context.Context, serverID int64, since time.Time) ([]HostMetric, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT server_id, ts, cpu, mem_used, mem_total, swap_used, swap_total, disk_used, disk_total, load1, net_rx_bps, net_tx_bps, net_rx_bytes, net_tx_bytes, peers_online FROM host_metrics WHERE server_id = ? AND ts >= ? ORDER BY ts`, serverID, since.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []HostMetric
	for rows.Next() {
		var m HostMetric
		var ts int64
		if err := rows.Scan(&m.ServerID, &ts, &m.CPU, &m.MemUsed, &m.MemTotal, &m.SwapUsed, &m.SwapTotal, &m.DiskUsed, &m.DiskTotal, &m.Load1, &m.NetRxBps, &m.NetTxBps, &m.NetRxBytes, &m.NetTxBytes, &m.PeersOnline); err != nil {
			return nil, err
		}
		m.TS = time.Unix(ts, 0)
		out = append(out, m)
	}
	return out, rows.Err()
}

// ---------- события ----------

// Event — строка events.
type Event struct {
	ID          int64
	TS          time.Time
	Kind        string
	Severity    string
	ServerID    int64
	InterfaceID int64
	PeerID      int64
	UserID      int64
	DeviceID    int64
	Message     string
	Payload     json.RawMessage
}

// AddEvent записывает событие (оповещение — забота модуля Telegram, M6).
func (s *Store) AddEvent(ctx context.Context, e Event) error {
	if len(e.Payload) == 0 {
		e.Payload = json.RawMessage("{}")
	}
	if e.TS.IsZero() {
		e.TS = time.Now()
	}
	if e.Severity == "" {
		e.Severity = "info"
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO events (ts, kind, severity, server_id, interface_id, peer_id, user_id, device_id, message, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.TS.Unix(), e.Kind, e.Severity, nullID(e.ServerID), nullID(e.InterfaceID), nullID(e.PeerID), nullID(e.UserID), nullID(e.DeviceID), e.Message, string(e.Payload))
	return err
}

// Events возвращает последние события. Страница журнала листает их через offset, поэтому
// одна страница не тащит в браузер всю историю.
func (s *Store) Events(ctx context.Context, limit int, offset ...int) ([]Event, error) {
	off := 0
	if len(offset) > 0 {
		off = offset[0]
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, kind, severity, COALESCE(server_id,0), COALESCE(interface_id,0), COALESCE(peer_id,0), COALESCE(user_id,0), COALESCE(device_id,0), message, payload FROM events ORDER BY ts DESC, id DESC LIMIT ? OFFSET ?`, limit, off)
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

// CountEvents — сколько всего событий (для пагинации журнала).
func (s *Store) CountEvents(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&n)
	return n, err
}

// TrafficSeries — суммарные дельты по интерфейсу по корзинам (для спарклайнов).
func (s *Store) TrafficSeries(ctx context.Context, ifaceID int64, since time.Time, bucket time.Duration) (ts []int64, rx []uint64, tx []uint64, err error) {
	b := int64(bucket.Seconds())
	// Самый крупный агрегат, который умеет обслужить корзину: часовые строки ложатся только в
	// корзину от часа, пятиминутки — от пяти минут. На парке из 600 устройств выбор источника
	// решает: сутки по пятиминуткам — это 177 тысяч строк на один график.
	table, col := "traffic_raw", "ts"
	switch {
	case bucket >= time.Hour:
		table, col = "traffic_1h", "bucket"
	case bucket >= 5*time.Minute || time.Since(since) > 6*time.Hour:
		table, col = "traffic_5m", "bucket"
	}
	rows, err := s.db.QueryContext(ctx, `SELECT t.`+col+` - t.`+col+` % ?, SUM(t.rx), SUM(t.tx) FROM `+table+` t
		JOIN peers p ON p.id = t.peer_id WHERE p.interface_id = ? AND t.`+col+` >= ? GROUP BY 1 ORDER BY 1`, b, ifaceID, since.Unix())
	if err != nil {
		return nil, nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var t int64
		var r, x uint64
		if err := rows.Scan(&t, &r, &x); err != nil {
			return nil, nil, nil, err
		}
		ts, rx, tx = append(ts, t), append(rx, r), append(tx, x)
	}
	return ts, rx, tx, rows.Err()
}

// Setting читает настройку (пусто, если нет).
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return v, err
}

// DefaultBrand — имя панели, пока администратор не задал своё.
const DefaultBrand = "awgdash"

const brandKey = "brand"

// Brand — как панель называет себя во вкладке браузера и в левом верхнем углу. Живёт в настройках,
// поэтому переживает перезапуск и переезд; при развёртывании в другой среде задаётся своё.
func (s *Store) Brand(ctx context.Context) (string, error) {
	v, err := s.Setting(ctx, brandKey)
	if err != nil {
		return DefaultBrand, err
	}
	if v = strings.TrimSpace(v); v == "" {
		return DefaultBrand, nil
	}
	return v, nil
}

// SetBrand задаёт имя панели. Пустая строка возвращает имя по умолчанию.
func (s *Store) SetBrand(ctx context.Context, name string) error {
	name = strings.TrimSpace(name)
	if n := len([]rune(name)); n > 32 {
		return fmt.Errorf("имя панели длиннее 32 символов (%d)", n)
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return errors.New("в имени панели есть управляющий символ")
		}
	}
	return s.SetSetting(ctx, brandKey, name)
}

// SetSetting пишет настройку.
func (s *Store) SetSetting(ctx context.Context, key, value string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// NormalizeList приводит «1.1.1.1,8.8.8.8» и «1.1.1.1, 8.8.8.8» к одному виду. Списки DNS и
// AllowedIPs приходят и из импорта чужих панелей, и из формы интерфейса, а импорт сравнивает их
// с умолчаниями интерфейса: разошедшийся пробел превратился бы в лишнее переопределение
// устройства (FR-11.1).
func NormalizeList(s string) string {
	var parts []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, ", ")
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullID(id int64) any {
	if id == 0 {
		return nil
	}
	return id
}

func nullInt(n sql.NullInt64) any {
	if !n.Valid {
		return nil
	}
	return n.Int64
}
