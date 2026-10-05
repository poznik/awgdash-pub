// Package importer — перенос пиров из чужих панелей в awgdash (SPEC §6.11).
//
// Импорт идемпотентен по публичному ключу и ничего не пишет на интерфейс: он только наполняет БД хаба,
// чтобы наблюдаемые пиры получили владельцев, имена и ключи для выдачи конфигов.
package importer

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/poznik/awgdash-pub/internal/store"
	"github.com/poznik/awgdash-pub/internal/wgkey"

	_ "modernc.org/sqlite"
)

// UnassignedUser — владелец по умолчанию для импортированных устройств: назначение живым
// пользователям делается в админке (FR-11.1).
const UnassignedUser = "Без владельца"

// Report — итог импорта; печатается CLI и показывается в админке.
type Report struct {
	Interface     string
	Source        string
	Total         int
	Created       []string
	Updated       []string
	Unchanged     []string
	Skipped       []string
	OnlyInRuntime []string // пиры на интерфейсе, которых нет в источнике
	OnlyInSource  []string // записи источника, которых нет на интерфейсе
	CreatedUsers  []string // владельцы, заведённые импортом (у wg-easy людей нет — они выводятся из имён)
	Notes         []string // что импорт решил за администратора: умолчания, endpoint, пропущенные поля
	DryRun        bool
}

// String — человекочитаемый отчёт.
func (r Report) String() string {
	var b strings.Builder
	mode := ""
	if r.DryRun {
		mode = " (примерка, ничего не записано)"
	}
	fmt.Fprintf(&b, "импорт %s → %s%s\n", r.Source, r.Interface, mode)
	fmt.Fprintf(&b, "  записей в источнике: %d\n", r.Total)
	line := func(title string, items []string) {
		if len(items) == 0 {
			return
		}
		fmt.Fprintf(&b, "  %s (%d): %s\n", title, len(items), strings.Join(items, ", "))
	}
	line("заведено пользователей", r.CreatedUsers)
	line("создано", r.Created)
	line("обновлено", r.Updated)
	line("без изменений", r.Unchanged)
	line("пропущено", r.Skipped)
	line("есть на интерфейсе, нет в источнике", r.OnlyInRuntime)
	line("есть в источнике, нет на интерфейсе", r.OnlyInSource)
	for _, n := range r.Notes {
		fmt.Fprintf(&b, "  · %s\n", n)
	}
	return b.String()
}

// peerRow — строка таблицы интерфейса в базе WGDashboard.
type peerRow struct {
	PublicKey    string
	PrivateKey   string
	PresharedKey string
	Name         string
	AllowedIP    string // адрес пира: 10.20.0.2/32
	DNS          string
	MTU          int
	Keepalive    int
	EndpointIPs  string // AllowedIPs клиентского конфига
	Notes        string
}

// Options — параметры импорта.
type Options struct {
	DBPath    string // путь к wgdashboard.db
	Interface string // имя интерфейса (оно же имя таблицы в источнике)
	Owner     string // кому назначить устройства; пусто — UnassignedUser
	DryRun    bool
}

// WGDashboard читает базу WGDashboard и заводит устройства в хабе.
// Файл открывается только на чтение: чужая панель может работать в этот момент.
func WGDashboard(ctx context.Context, st *store.Store, iface store.Interface, opt Options) (Report, error) {
	rep := Report{Interface: iface.Name, Source: opt.DBPath, DryRun: opt.DryRun}
	rows, err := readPeers(ctx, opt.DBPath, opt.Interface)
	if err != nil {
		return rep, err
	}
	rep.Total = len(rows)

	runtime := map[string]bool{}
	peers, err := st.Peers(ctx, iface.ID, false)
	if err != nil {
		return rep, err
	}
	for _, p := range peers {
		runtime[p.PublicKey] = true
	}

	owner := strings.TrimSpace(opt.Owner)
	if owner == "" {
		owner = UnassignedUser
	}
	ownerID, err := ensureUser(ctx, st, owner, opt.DryRun)
	if err != nil {
		return rep, err
	}

	seen := map[string]bool{}
	for _, r := range rows {
		label := r.Name
		if label == "" {
			label = shortKey(r.PublicKey)
		}
		if !wgkey.Valid(r.PublicKey) {
			rep.Skipped = append(rep.Skipped, label+": публичный ключ не разобран")
			continue
		}
		seen[r.PublicKey] = true
		if !runtime[r.PublicKey] {
			rep.OnlyInSource = append(rep.OnlyInSource, label)
		}
		addr, err := addressOf(r.AllowedIP)
		if err != nil {
			rep.Skipped = append(rep.Skipped, label+": "+err.Error())
			continue
		}
		if r.PrivateKey != "" {
			if pub, err := wgkey.Public(r.PrivateKey); err != nil || pub != r.PublicKey {
				rep.Skipped = append(rep.Skipped, label+": приватный ключ не соответствует публичному")
				continue
			}
		}
		dev := store.Device{
			UserID:       ownerID,
			InterfaceID:  iface.ID,
			Name:         deviceName(r.Name, r.PublicKey),
			Preset:       store.PresetPhone,
			PrivateKey:   r.PrivateKey,
			PublicKey:    r.PublicKey,
			PresharedKey: r.PresharedKey,
			Address:      addr,
			Overrides:    overridesOf(r, iface),
			CreatedBy:    "import",
			Note:         strings.TrimSpace(r.Notes),
		}
		if dev.Overrides.AllowedIPs != "" {
			// Список отличается от умолчания интерфейса — сохраняем как есть, чтобы выданный
			// конфиг совпал с прежним (FR-11.4).
			dev.Preset = store.PresetCustom
		}
		existing, err := st.DeviceByPublicKey(ctx, iface.ID, r.PublicKey)
		switch {
		case err == nil:
			changed, err := updateExisting(ctx, st, existing, dev, opt.DryRun)
			if err != nil {
				rep.Skipped = append(rep.Skipped, label+": "+err.Error())
				continue
			}
			if changed {
				rep.Updated = append(rep.Updated, existing.Name)
			} else {
				rep.Unchanged = append(rep.Unchanged, existing.Name)
			}
		case err == store.ErrNotFound:
			if opt.DryRun {
				rep.Created = append(rep.Created, dev.Name)
				continue
			}
			if _, err := st.CreateDevice(ctx, dev); err != nil {
				rep.Skipped = append(rep.Skipped, label+": "+err.Error())
				continue
			}
			rep.Created = append(rep.Created, dev.Name)
		default:
			return rep, err
		}
	}
	for _, p := range peers {
		if !seen[p.PublicKey] {
			rep.OnlyInRuntime = append(rep.OnlyInRuntime, shortKey(p.PublicKey)+" ("+p.AllowedIPs+")")
		}
	}
	if !opt.DryRun {
		if _, err := st.LinkPeers(ctx, iface.ID); err != nil {
			return rep, err
		}
	}
	sort.Strings(rep.Created)
	sort.Strings(rep.Updated)
	sort.Strings(rep.Unchanged)
	return rep, nil
}

// updateExisting дописывает импортированному устройству то, чего у него нет: ключи, адрес,
// переопределения. Имя и владельца, назначенные администратором, импорт не трогает (FR-11.3).
func updateExisting(ctx context.Context, st *store.Store, cur, fresh store.Device, dryRun bool) (bool, error) {
	changed := false
	if cur.PrivateKey == "" && fresh.PrivateKey != "" {
		changed = true
	}
	if cur.PresharedKey != fresh.PresharedKey && fresh.PresharedKey != "" {
		changed = true
	}
	if cur.Overrides != fresh.Overrides {
		changed = true
	}
	if !changed || dryRun {
		return changed, nil
	}
	if cur.PrivateKey == "" && fresh.PrivateKey != "" {
		if err := st.RotateKeys(ctx, cur.ID, fresh.PrivateKey, cur.PublicKey, firstNonEmpty(fresh.PresharedKey, cur.PresharedKey)); err != nil {
			return false, err
		}
	}
	upd := cur
	upd.Overrides = fresh.Overrides
	if cur.Preset == store.PresetPhone && fresh.Preset == store.PresetCustom {
		upd.Preset = store.PresetCustom
	}
	if err := st.UpdateDevice(ctx, upd); err != nil {
		return false, err
	}
	return true, nil
}

// overridesOf оставляет только то, что отличается от умолчаний интерфейса: иначе карточка
// устройства заполняется переопределениями, повторяющими интерфейс.
func overridesOf(r peerRow, iface store.Interface) store.Overrides {
	var ov store.Overrides
	if v := store.NormalizeList(r.DNS); v != "" && v != store.NormalizeList(iface.DefaultDNS) {
		ov.DNS = v
	}
	if r.MTU > 0 && r.MTU != iface.MTU {
		ov.MTU = r.MTU
	}
	if r.Keepalive > 0 && r.Keepalive != iface.DefaultKeepalive {
		ov.Keepalive = r.Keepalive
	}
	if v := store.NormalizeList(r.EndpointIPs); v != "" && v != store.NormalizeList(iface.DefaultAllowedIPs) {
		ov.AllowedIPs = v
	}
	return ov
}

// ensureUser находит или заводит пользователя-владельца импортированных устройств.
func ensureUser(ctx context.Context, st *store.Store, name string, dryRun bool) (int64, error) {
	u, err := st.UserByName(ctx, name)
	if err == nil {
		return u.ID, nil
	}
	if err != store.ErrNotFound {
		return 0, err
	}
	if dryRun {
		return 0, nil
	}
	// Заметка остаётся пустой: она место для того, что администратор напишет о человеке сам,
	// а откуда пришли устройства, видно в аудите и в поле «создано» у каждого из них.
	id, _, err := st.CreateUser(ctx, store.User{Name: name, MaxDevices: 1000})
	return id, err
}

// deviceName приводит имя из чужой панели к правилам FR-3.8, не теряя узнаваемости.
func deviceName(name, pub string) string {
	name = strings.TrimSpace(name)
	var b strings.Builder
	for _, r := range name {
		switch {
		case r == '_' || r == '-' || r == '.' || r == ' ':
			b.WriteRune(r)
		default:
			if store.ValidDeviceName(string(r)) == nil {
				b.WriteRune(r)
			} else {
				b.WriteRune('-')
			}
		}
	}
	out := strings.TrimSpace(b.String())
	if rs := []rune(out); len(rs) > 32 {
		out = strings.TrimSpace(string(rs[:32]))
	}
	if out == "" {
		out = "пир " + shortKey(pub)
	}
	return out
}

// addressOf вытаскивает адрес пира из allowed_ip источника: берётся первый /32.
func addressOf(allowed string) (string, error) {
	for _, p := range strings.Split(allowed, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		host, _, _ := strings.Cut(p, "/")
		if host != "" {
			return host, nil
		}
	}
	return "", fmt.Errorf("нет адреса в allowed_ip %q", allowed)
}

func shortKey(k string) string {
	if len(k) <= 12 {
		return k
	}
	return k[:6] + "…" + k[len(k)-4:]
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// readPeers читает таблицу интерфейса из базы WGDashboard (файл открывается только на чтение).
func readPeers(ctx context.Context, path, table string) ([]peerRow, error) {
	if strings.ContainsAny(table, `"[]`) {
		return nil, fmt.Errorf("недопустимое имя интерфейса %q", table)
	}
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("база %s: %w", path, err)
	}
	defer db.Close()
	var exists int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&exists); err != nil {
		return nil, fmt.Errorf("база %s: %w", path, err)
	}
	if exists == 0 {
		return nil, fmt.Errorf("в базе %s нет таблицы %q — это база WGDashboard с интерфейсом %s?", path, table, table)
	}
	q := fmt.Sprintf(`SELECT id, COALESCE(private_key,''), COALESCE(preshared_key,''), COALESCE(name,''), COALESCE(allowed_ip,''),
		COALESCE("DNS",''), COALESCE(mtu,0), COALESCE(keepalive,0), COALESCE(endpoint_allowed_ip,''), COALESCE(notes,'')
		FROM "%s" ORDER BY allowed_ip`, table)
	rows, err := db.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("чтение %s: %w", table, err)
	}
	defer rows.Close()
	var out []peerRow
	for rows.Next() {
		var r peerRow
		var mtu, keepalive sql.NullString
		if err := rows.Scan(&r.PublicKey, &r.PrivateKey, &r.PresharedKey, &r.Name, &r.AllowedIP, &r.DNS, &mtu, &keepalive, &r.EndpointIPs, &r.Notes); err != nil {
			return nil, err
		}
		r.MTU = atoi(mtu.String)
		r.Keepalive = atoi(keepalive.String)
		out = append(out, r)
	}
	return out, rows.Err()
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}
