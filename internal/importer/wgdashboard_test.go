package importer

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/poznik/awgdash-pub/internal/clientconf"
	"github.com/poznik/awgdash-pub/internal/store"
	"github.com/poznik/awgdash-pub/internal/wgkey"
)

// Схема — фактическая из WGDashboard v4.3.3 (таблица названа именем интерфейса).
const wgdashSchema = `CREATE TABLE "%s" (
	id VARCHAR(255) NOT NULL,
	private_key VARCHAR(255),
	"DNS" TEXT,
	endpoint_allowed_ip TEXT,
	name TEXT,
	total_receive FLOAT,
	total_sent FLOAT,
	total_data FLOAT,
	endpoint VARCHAR(255),
	status VARCHAR(255),
	latest_handshake VARCHAR(255),
	allowed_ip VARCHAR(255),
	cumu_receive FLOAT,
	cumu_sent FLOAT,
	cumu_data FLOAT,
	mtu INTEGER,
	keepalive INTEGER,
	notes TEXT,
	remote_endpoint VARCHAR(255),
	preshared_key VARCHAR(255),
	PRIMARY KEY (id)
)`

type srcPeer struct {
	pair      wgkey.Pair
	name      string
	addr      string
	dns       string
	mtu       int
	keepalive int
	eaip      string
	psk       string
}

func makeSource(t *testing.T, iface string, peers []srcPeer) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wgdashboard.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(fmt.Sprintf(wgdashSchema, iface)); err != nil {
		t.Fatal(err)
	}
	for _, p := range peers {
		_, err := db.Exec(fmt.Sprintf(`INSERT INTO "%s" (id, private_key, "DNS", endpoint_allowed_ip, name, allowed_ip, mtu, keepalive, notes, remote_endpoint, preshared_key, status)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, '', 'vpn.example.com', ?, 'running')`, iface),
			p.pair.Public, p.pair.Private, p.dns, p.eaip, p.name, p.addr, p.mtu, p.keepalive, p.psk)
		if err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func openHub(t *testing.T) (*store.Store, store.Interface) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	srv, err := st.UpsertLocalServer(ctx, "de", "Германия")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertInterface(ctx, srv, "awg-old", store.InterfaceFacts{
		Subnet: "10.20.0.0/16", ServerAddress: "10.20.0.1/16", ListenPort: 443, MTU: 1280, IsAWG: true,
		ServerPublicKey: "SERVERPUBKEYSERVERPUBKEYSERVERPUBKEYSERVERP=",
		Obfuscation:     map[string]string{"Jc": "6", "Jmin": "50", "Jmax": "1000", "S1": "77", "S2": "99", "H1": "1", "H2": "2", "H3": "3", "H4": "4", "I1": "<b 0xf1>"},
	}); err != nil {
		t.Fatal(err)
	}
	list, err := st.Interfaces(ctx, srv)
	if err != nil || len(list) != 1 {
		t.Fatalf("interfaces = %+v, err = %v", list, err)
	}
	return st, list[0]
}

// samplePeers — пять пиров по образцу awg-old: единые DNS/MTU/keepalive, AllowedIPs 0.0.0.0/0.
func samplePeers(t *testing.T) []srcPeer {
	t.Helper()
	names := []string{"Alex iPhone", "Alex Home Router", "Guest Home Router", "Maria Ivanova Phone", "Alex Laptop"}
	out := make([]srcPeer, 0, len(names))
	for i, n := range names {
		pair, err := wgkey.Generate()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, srcPeer{pair: pair, name: n, addr: fmt.Sprintf("10.20.0.%d/32", i+2),
			dns: "1.1.1.1,8.8.8.8", mtu: 1280, keepalive: 21, eaip: "0.0.0.0/0"})
	}
	return out
}

func TestImportCreatesDevices(t *testing.T) {
	ctx := context.Background()
	st, iface := openHub(t)
	peers := samplePeers(t)
	src := makeSource(t, "awg-old", peers)

	rep, err := WGDashboard(ctx, st, iface, Options{DBPath: src, Interface: "awg-old"})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Total != 5 || len(rep.Created) != 5 || len(rep.Skipped) != 0 {
		t.Fatalf("отчёт: %+v", rep)
	}
	// Пиров на интерфейсе ещё нет — все записи источника числятся отсутствующими в рантайме.
	if len(rep.OnlyInSource) != 5 || len(rep.OnlyInRuntime) != 0 {
		t.Fatalf("расхождения с рантаймом: %+v", rep)
	}
	owner, err := st.UserByName(ctx, UnassignedUser)
	if err != nil {
		t.Fatal(err)
	}
	devs, err := st.DevicesByUser(ctx, owner.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 5 {
		t.Fatalf("устройств у владельца по умолчанию: %d", len(devs))
	}
	byName := map[string]store.Device{}
	for _, d := range devs {
		byName[d.Name] = d
	}
	d, ok := byName["Alex iPhone"]
	if !ok {
		t.Fatalf("нет устройства с именем из источника: %v", byName)
	}
	if d.Address != "10.20.0.2" || d.CreatedBy != "import" || d.Preset != store.PresetPhone {
		t.Fatalf("устройство: %+v", d)
	}
	// DNS/MTU/keepalive совпали с умолчаниями интерфейса — переопределений быть не должно.
	if d.Overrides != (store.Overrides{}) {
		t.Fatalf("лишние переопределения: %+v", d.Overrides)
	}
	if pub, err := wgkey.Public(d.PrivateKey); err != nil || pub != d.PublicKey {
		t.Fatalf("ключи устройства не сходятся: %v", err)
	}
}

func TestImportIsIdempotent(t *testing.T) {
	ctx := context.Background()
	st, iface := openHub(t)
	peers := samplePeers(t)
	src := makeSource(t, "awg-old", peers)

	if _, err := WGDashboard(ctx, st, iface, Options{DBPath: src, Interface: "awg-old"}); err != nil {
		t.Fatal(err)
	}
	// Администратор переименовал устройство и передал его живому пользователю.
	owner, _ := st.UserByName(ctx, UnassignedUser)
	devs, _ := st.DevicesByUser(ctx, owner.ID)
	sort.Slice(devs, func(i, j int) bool { return devs[i].Address < devs[j].Address })
	nikID, _, err := st.CreateUser(ctx, store.User{Name: "Анна"})
	if err != nil {
		t.Fatal(err)
	}
	moved := devs[0]
	moved.Name, moved.UserID = "Телефон", nikID
	if err := st.UpdateDevice(ctx, moved); err != nil {
		t.Fatal(err)
	}

	rep, err := WGDashboard(ctx, st, iface, Options{DBPath: src, Interface: "awg-old"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Created) != 0 || len(rep.Updated) != 0 || len(rep.Unchanged) != 5 {
		t.Fatalf("повторный импорт что-то поменял: %+v", rep)
	}
	after, err := st.DeviceByID(ctx, moved.ID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Name != "Телефон" || after.UserID != nikID {
		t.Fatalf("импорт перезаписал имя или владельца: %+v", after)
	}
}

func TestImportOverridesAndSkips(t *testing.T) {
	ctx := context.Background()
	st, iface := openHub(t)
	peers := samplePeers(t)
	// Роутер с собственным списком AllowedIPs и своим MTU.
	peers[1].eaip = "0.0.0.0/5, 8.0.0.0/7"
	peers[1].mtu = 1420
	peers[1].keepalive = 25
	peers[1].dns = "9.9.9.9"
	// Битая запись: приватный ключ от другой пары.
	other, _ := wgkey.Generate()
	peers[2].pair.Private = other.Private
	// Запись без адреса.
	peers[3].addr = ""
	src := makeSource(t, "awg-old", peers)

	rep, err := WGDashboard(ctx, st, iface, Options{DBPath: src, Interface: "awg-old", Owner: "Анна"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Created) != 3 || len(rep.Skipped) != 2 {
		t.Fatalf("отчёт: %+v", rep)
	}
	if !strings.Contains(strings.Join(rep.Skipped, " "), "не соответствует") {
		t.Fatalf("нет причины пропуска по ключу: %v", rep.Skipped)
	}
	u, err := st.UserByName(ctx, "Анна")
	if err != nil {
		t.Fatal(err)
	}
	devs, _ := st.DevicesByUser(ctx, u.ID)
	var router store.Device
	for _, d := range devs {
		if d.Name == "Alex Home Router" {
			router = d
		}
	}
	if router.ID == 0 {
		t.Fatalf("роутер не импортирован: %+v", devs)
	}
	if router.Preset != store.PresetCustom {
		t.Fatalf("свой список AllowedIPs должен давать пресет custom: %+v", router)
	}
	want := store.Overrides{AllowedIPs: "0.0.0.0/5, 8.0.0.0/7", DNS: "9.9.9.9", MTU: 1420, Keepalive: 25}
	if router.Overrides != want {
		t.Fatalf("переопределения роутера = %+v, ожидалось %+v", router.Overrides, want)
	}
}

func TestImportDryRun(t *testing.T) {
	ctx := context.Background()
	st, iface := openHub(t)
	src := makeSource(t, "awg-old", samplePeers(t))
	rep, err := WGDashboard(ctx, st, iface, Options{DBPath: src, Interface: "awg-old", DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Created) != 5 {
		t.Fatalf("примерка: %+v", rep)
	}
	if _, err := st.UserByName(ctx, UnassignedUser); err != store.ErrNotFound {
		t.Fatalf("примерка завела пользователя: %v", err)
	}
	list, total, _ := st.Users(ctx, store.UserFilter{})
	if total != 0 || len(list) != 0 {
		t.Fatalf("примерка что-то записала: %+v", list)
	}
}

func TestImportSourceErrors(t *testing.T) {
	ctx := context.Background()
	st, iface := openHub(t)
	src := makeSource(t, "awg-old", samplePeers(t))
	if _, err := WGDashboard(ctx, st, iface, Options{DBPath: src, Interface: "awg-other"}); err == nil {
		t.Fatal("принят интерфейс, которого нет в источнике")
	}
	if _, err := WGDashboard(ctx, st, iface, Options{DBPath: filepath.Join(t.TempDir(), "нет.db"), Interface: "awg-old"}); err == nil {
		t.Fatal("принята несуществующая база")
	}
	if _, err := WGDashboard(ctx, st, iface, Options{DBPath: src, Interface: `awg"; DROP TABLE users; --`}); err == nil {
		t.Fatal("принято имя таблицы с кавычками")
	}
}

// FR-11.4: конфиг, выданный панелью импортированному устройству, совпадает с прежним
// по всем строкам, кроме незаданных I-пакетов.
func TestImportedConfigMatchesSource(t *testing.T) {
	ctx := context.Background()
	st, iface := openHub(t)
	peers := samplePeers(t)
	src := makeSource(t, "awg-old", peers)
	if _, err := WGDashboard(ctx, st, iface, Options{DBPath: src, Interface: "awg-old"}); err != nil {
		t.Fatal(err)
	}
	iface.Endpoints = []store.Endpoint{{Label: "основной", Host: "vpn.example.com", Port: 443, Primary: true}}
	iface.DefaultDNS = "1.1.1.1, 8.8.8.8"
	iface.DefaultKeepalive = 21

	owner, _ := st.UserByName(ctx, UnassignedUser)
	devs, _ := st.DevicesByUser(ctx, owner.ID)
	var d store.Device
	for _, x := range devs {
		if x.Address == "10.20.0.2" {
			d = x
		}
	}
	if d.ID == 0 {
		t.Fatal("устройство 10.20.0.2 не найдено")
	}
	ep, _ := clientconf.EndpointByLabel(iface, "")
	got, err := clientconf.Build(iface, d, ep)
	if err != nil {
		t.Fatal(err)
	}
	// Прежний конфиг: так его отдавал WGDashboard для этого пира.
	prev := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.20.0.2/32
DNS = 1.1.1.1,8.8.8.8
MTU = 1280
Jc = 6
Jmin = 50
Jmax = 1000
S1 = 77
S2 = 99
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <b 0xf1>
I2 = 0
I3 = 0

[Peer]
PublicKey = SERVERPUBKEYSERVERPUBKEYSERVERPUBKEYSERVERP=
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:443
PersistentKeepalive = 21
`, peers[0].pair.Private)

	oldKV, newKV := configKV(prev), configKV(got)
	for k, v := range oldKV {
		if strings.HasPrefix(k, "I") && (v == "0" || v == "") {
			continue // I2..I5 намеренно выброшены (FR-4.2)
		}
		if newKV[k] != v {
			t.Fatalf("строка %s: было %q, стало %q\n--- новый конфиг ---\n%s", k, v, newKV[k], got)
		}
	}
	for k, v := range newKV {
		if _, ok := oldKV[k]; !ok {
			t.Fatalf("в новом конфиге появилась строка %s = %q:\n%s", k, v, got)
		}
	}
}

// configKV разбирает конфиг в пары ключ→значение; списки нормализуются, чтобы «1.1.1.1,8.8.8.8»
// и «1.1.1.1, 8.8.8.8» считались одним и тем же.
func configKV(conf string) map[string]string {
	out := map[string]string{}
	section := ""
	for _, line := range strings.Split(conf, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") {
			section = strings.Trim(line, "[]")
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[section+"."+strings.TrimSpace(k)] = store.NormalizeList(strings.TrimSpace(v))
	}
	return out
}
