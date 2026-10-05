package importer

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/poznik/awgdash-pub/internal/store"
	"github.com/poznik/awgdash-pub/internal/wgkey"
)

// WGEasyOptions — параметры импорта из wg-easy.
type WGEasyOptions struct {
	DBPath string // путь к wg-easy.db (открывается только на чтение)
	Source string // имя интерфейса в базе-источнике (у wg-easy это «wg0»); пусто — единственный
	Owner  string // всех устройств одному владельцу; пусто — владелец из имени устройства
	DryRun bool
}

// wgEasyDefaults — умолчания интерфейса из wg-easy: из них собирался конфиг каждого клиента,
// поэтому панель обязана принять их как свои, иначе перевыдача даст человеку другой файл.
type wgEasyDefaults struct {
	DNS        string
	AllowedIPs string
	Keepalive  int
	MTU        int
	Host       string
	Port       int
}

// WGEasy читает базу wg-easy и заводит в хабе пользователей и устройства (FR-11.1).
//
// В wg-easy людей нет: все пиры принадлежат одному аккаунту панели, а владелец различим только по
// имени устройства — «Имя.Фамилия телефон». Поэтому владелец берётся из первого слова имени, а
// остаток становится именем устройства. Интерфейс при импорте не трогается ни в каком режиме.
func WGEasy(ctx context.Context, st *store.Store, iface store.Interface, opt WGEasyOptions) (Report, error) {
	rep := Report{Interface: iface.Name, Source: opt.DBPath, DryRun: opt.DryRun}
	db, err := sql.Open("sqlite", "file:"+opt.DBPath+"?mode=ro&_pragma=busy_timeout(5000)")
	if err != nil {
		return rep, fmt.Errorf("база %s: %w", opt.DBPath, err)
	}
	defer db.Close()

	src, serverPub, err := wgEasyInterface(ctx, db, opt.Source)
	if err != nil {
		return rep, err
	}
	// Защита от импорта не туда: база другого сервера завела бы 62 устройства с чужими ключами.
	if iface.ServerPublicKey != "" && serverPub != "" && iface.ServerPublicKey != serverPub {
		return rep, fmt.Errorf("база описывает интерфейс %q с ключом сервера %s, а у %s ключ %s — это база другого сервера",
			src, shortKey(serverPub), iface.Name, shortKey(iface.ServerPublicKey))
	}
	if serverPub == "" || iface.ServerPublicKey == "" {
		rep.Notes = append(rep.Notes, "ключ сервера сверить не с чем — проверь глазами, что база от того же интерфейса")
	}

	def, err := wgEasyDefaultsOf(ctx, db, src)
	if err != nil {
		return rep, err
	}
	// Умолчания выставляются до разбора клиентов: переопределения устройства считаются
	// относительно них, иначе у каждого появится лишний DNS и keepalive.
	iface, err = applyWGEasyDefaults(ctx, st, iface, def, &rep)
	if err != nil {
		return rep, err
	}

	rows, err := wgEasyClients(ctx, db, src)
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

	owners := map[string]int64{}
	seen := map[string]bool{}
	for _, r := range rows {
		owner, devName := splitOwner(r.Name)
		if opt.Owner != "" {
			owner, devName = opt.Owner, r.Name
		}
		label := owner + " / " + devName
		if !wgkey.Valid(r.PublicKey) {
			rep.Skipped = append(rep.Skipped, label+": публичный ключ не разобран")
			continue
		}
		if r.PrivateKey != "" {
			if pub, err := wgkey.Public(r.PrivateKey); err != nil || pub != r.PublicKey {
				rep.Skipped = append(rep.Skipped, label+": приватный ключ не соответствует публичному")
				continue
			}
		}
		addr, err := addressOf(r.Address)
		if err != nil {
			rep.Skipped = append(rep.Skipped, label+": "+err.Error())
			continue
		}
		if r.ExpiresAt != "" {
			rep.Notes = append(rep.Notes, label+": в wg-easy стоял срок до "+r.ExpiresAt+" — в панели сроков у устройств нет")
		}
		seen[r.PublicKey] = true
		if !runtime[r.PublicKey] {
			rep.OnlyInSource = append(rep.OnlyInSource, label)
		}

		ownerID, ok := owners[owner]
		if !ok {
			_, errBefore := st.UserByName(ctx, owner)
			id, err := ensureUser(ctx, st, owner, opt.DryRun)
			if err != nil {
				rep.Skipped = append(rep.Skipped, label+": владелец: "+err.Error())
				continue
			}
			if errBefore == store.ErrNotFound {
				rep.CreatedUsers = append(rep.CreatedUsers, owner)
			}
			owners[owner] = id
			ownerID = id
		}

		dev := store.Device{
			UserID:       ownerID,
			InterfaceID:  iface.ID,
			Name:         deviceName(devName, r.PublicKey),
			Preset:       store.PresetPhone,
			PrivateKey:   r.PrivateKey,
			PublicKey:    r.PublicKey,
			PresharedKey: r.PresharedKey,
			Address:      addr,
			Overrides:    wgEasyOverrides(r, iface),
			Status:       "active",
			CreatedBy:    "import",
		}
		if !r.Enabled {
			dev.Status = "disabled"
		}
		if dev.Overrides.AllowedIPs != "" {
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
				rep.Updated = append(rep.Updated, label)
			} else {
				rep.Unchanged = append(rep.Unchanged, label)
			}
		case err == store.ErrNotFound:
			if opt.DryRun {
				rep.Created = append(rep.Created, label)
				continue
			}
			if _, err := st.CreateDevice(ctx, dev); err != nil {
				rep.Skipped = append(rep.Skipped, label+": "+err.Error())
				continue
			}
			rep.Created = append(rep.Created, label)
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
	sort.Strings(rep.CreatedUsers)
	return rep, nil
}

// splitOwner делит имя wg-easy на владельца и устройство: «Ivan.Petrov n1» → «Ivan.Petrov» и «n1».
// Имя из одного слова целиком становится и владельцем, и устройством — человек с одним устройством
// не должен получить пустую карточку.
func splitOwner(name string) (owner, device string) {
	name = strings.TrimSpace(name)
	owner, device, ok := strings.Cut(name, " ")
	if !ok || strings.TrimSpace(device) == "" {
		return name, name
	}
	return owner, strings.TrimSpace(device)
}

// wgEasyOverrides оставляет только отличия от умолчаний интерфейса (у wg-easy почти всё пусто и
// берётся из умолчаний, кроме MTU: он прописан каждому клиенту).
func wgEasyOverrides(r wgEasyRow, iface store.Interface) store.Overrides {
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
	if v := store.NormalizeList(r.AllowedIPs); v != "" && v != store.NormalizeList(iface.DefaultAllowedIPs) {
		ov.AllowedIPs = v
	}
	return ov
}

// applyWGEasyDefaults переносит умолчания источника в интерфейс панели и возвращает обновлённую копию.
// Уже заданные значения не затираются молча: расхождение попадает в отчёт.
func applyWGEasyDefaults(ctx context.Context, st *store.Store, iface store.Interface, def wgEasyDefaults, rep *Report) (store.Interface, error) {
	want := iface
	if def.DNS != "" {
		want.DefaultDNS = def.DNS
	}
	if def.AllowedIPs != "" {
		want.DefaultAllowedIPs = def.AllowedIPs
	}
	if def.Keepalive > 0 {
		want.DefaultKeepalive = def.Keepalive
	}
	if want.DefaultDNS != iface.DefaultDNS || want.DefaultAllowedIPs != iface.DefaultAllowedIPs || want.DefaultKeepalive != iface.DefaultKeepalive {
		rep.Notes = append(rep.Notes, fmt.Sprintf("умолчания интерфейса приведены к wg-easy: DNS %q, AllowedIPs %q, keepalive %d",
			want.DefaultDNS, want.DefaultAllowedIPs, want.DefaultKeepalive))
		if !rep.DryRun {
			if err := st.SetInterfaceDefaults(ctx, iface.ID, want.DefaultDNS, want.DefaultKeepalive, want.DefaultAllowedIPs); err != nil {
				return iface, err
			}
		}
	}
	if def.Host != "" && def.Port > 0 && len(iface.Endpoints) == 0 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("endpoint интерфейса взят из wg-easy: %s:%d", def.Host, def.Port))
		if !rep.DryRun {
			eps := []store.Endpoint{{Label: "основной", Host: def.Host, Port: def.Port, Primary: true}}
			if err := st.SetEndpoints(ctx, iface.ID, eps); err != nil {
				return iface, err
			}
			want.Endpoints = eps
		}
	}
	return want, nil
}

// wgEasyRow — клиент из clients_table.
type wgEasyRow struct {
	Name         string
	Address      string
	PublicKey    string
	PrivateKey   string
	PresharedKey string
	DNS          string
	AllowedIPs   string
	MTU          int
	Keepalive    int
	Enabled      bool
	ExpiresAt    string
}

// wgEasyInterface выбирает интерфейс источника и возвращает его имя и публичный ключ сервера.
func wgEasyInterface(ctx context.Context, db *sql.DB, want string) (string, string, error) {
	var exists int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'clients_table'`).Scan(&exists); err != nil {
		return "", "", fmt.Errorf("чтение базы: %w", err)
	}
	if exists == 0 {
		return "", "", fmt.Errorf("в базе нет таблицы clients_table — это база wg-easy 15?")
	}
	rows, err := db.QueryContext(ctx, `SELECT name, COALESCE(public_key, '') FROM interfaces_table ORDER BY name`)
	if err != nil {
		return "", "", fmt.Errorf("чтение interfaces_table: %w", err)
	}
	defer rows.Close()
	found := map[string]string{}
	var names []string
	for rows.Next() {
		var n, pub string
		if err := rows.Scan(&n, &pub); err != nil {
			return "", "", err
		}
		found[n] = pub
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		return "", "", err
	}
	switch {
	case want != "":
		pub, ok := found[want]
		if !ok {
			return "", "", fmt.Errorf("в базе нет интерфейса %q, есть: %s", want, strings.Join(names, ", "))
		}
		return want, pub, nil
	case len(names) == 1:
		return names[0], found[names[0]], nil
	case len(names) == 0:
		return "", "", fmt.Errorf("в базе нет ни одного интерфейса")
	default:
		return "", "", fmt.Errorf("в базе несколько интерфейсов (%s) — задай --source", strings.Join(names, ", "))
	}
}

// wgEasyDefaultsOf читает умолчания интерфейса-источника.
func wgEasyDefaultsOf(ctx context.Context, db *sql.DB, src string) (wgEasyDefaults, error) {
	var d wgEasyDefaults
	var dns, allowed sql.NullString
	err := db.QueryRowContext(ctx, `SELECT COALESCE(default_dns, ''), COALESCE(default_allowed_ips, ''), COALESCE(default_persistent_keepalive, 0),
		COALESCE(default_mtu, 0), COALESCE(host, ''), COALESCE(port, 0) FROM user_configs_table WHERE id = ?`, src).
		Scan(&dns, &allowed, &d.Keepalive, &d.MTU, &d.Host, &d.Port)
	if err == sql.ErrNoRows {
		return d, nil // умолчаний нет — возьмём те, что уже стоят у интерфейса
	}
	if err != nil {
		return d, fmt.Errorf("чтение user_configs_table: %w", err)
	}
	d.DNS, d.AllowedIPs = jsonList(dns.String), jsonList(allowed.String)
	return d, nil
}

// wgEasyClients читает клиентов интерфейса-источника.
func wgEasyClients(ctx context.Context, db *sql.DB, src string) ([]wgEasyRow, error) {
	q := `SELECT COALESCE(name, ''), COALESCE(ipv4_address, ''), COALESCE(public_key, ''), COALESCE(private_key, ''),
		COALESCE(pre_shared_key, ''), COALESCE(dns, ''), COALESCE(allowed_ips, ''), COALESCE(mtu, 0),
		COALESCE(persistent_keepalive, 0), COALESCE(enabled, 1), COALESCE(expires_at, '')
		FROM clients_table WHERE interface_id = ? ORDER BY id`
	rows, err := db.QueryContext(ctx, q, src)
	if err != nil {
		return nil, fmt.Errorf("чтение clients_table: %w", err)
	}
	defer rows.Close()
	var out []wgEasyRow
	for rows.Next() {
		var r wgEasyRow
		var dns, allowed string
		var enabled int
		if err := rows.Scan(&r.Name, &r.Address, &r.PublicKey, &r.PrivateKey, &r.PresharedKey,
			&dns, &allowed, &r.MTU, &r.Keepalive, &enabled, &r.ExpiresAt); err != nil {
			return nil, err
		}
		r.DNS, r.AllowedIPs, r.Enabled = jsonList(dns), jsonList(allowed), enabled != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

// jsonList превращает хранимый wg-easy JSON-массив («["1.1.1.1","8.8.8.8"]») в «1.1.1.1, 8.8.8.8».
// Строка без скобок принимается как есть: у части записей поле заполнено вручную.
func jsonList(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || s == "null" {
		return ""
	}
	if !strings.HasPrefix(s, "[") {
		return store.NormalizeList(s)
	}
	var items []string
	if err := json.Unmarshal([]byte(s), &items); err != nil {
		return store.NormalizeList(strings.Trim(s, "[]"))
	}
	return store.NormalizeList(strings.Join(items, ", "))
}
