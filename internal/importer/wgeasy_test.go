package importer

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/poznik/awgdash-pub/internal/clientconf"
	"github.com/poznik/awgdash-pub/internal/store"
	"github.com/poznik/awgdash-pub/internal/wgkey"
)

// Схема — фактическая из wg-easy 15.3.0 (drizzle): клиенты, интерфейсы и умолчания выдачи.
const wgEasySchema = `
CREATE TABLE interfaces_table (
	name text PRIMARY KEY NOT NULL,
	device text NOT NULL,
	port integer NOT NULL,
	private_key text NOT NULL,
	public_key text NOT NULL,
	ipv4_cidr text NOT NULL,
	ipv6_cidr text NOT NULL,
	mtu integer NOT NULL,
	j_c integer, j_min integer, j_max integer,
	s1 integer, s2 integer, s3 integer, s4 integer,
	h1 text, h2 text, h3 text, h4 text,
	i1 text, i2 text, i3 text, i4 text, i5 text,
	enabled integer NOT NULL,
	created_at text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	updated_at text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	firewall_enabled integer DEFAULT false NOT NULL
);
CREATE TABLE user_configs_table (
	id text PRIMARY KEY NOT NULL,
	default_mtu integer NOT NULL,
	default_persistent_keepalive integer NOT NULL,
	default_dns text NOT NULL,
	default_allowed_ips text NOT NULL,
	host text NOT NULL,
	port integer NOT NULL,
	created_at text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	updated_at text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	default_j_c integer DEFAULT 7, default_j_min integer DEFAULT 10, default_j_max integer DEFAULT 1000,
	default_i1 text, default_i2 text, default_i3 text, default_i4 text, default_i5 text
);
CREATE TABLE clients_table (
	id integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	user_id integer NOT NULL,
	interface_id text NOT NULL,
	name text NOT NULL,
	ipv4_address text NOT NULL,
	ipv6_address text NOT NULL,
	pre_up text DEFAULT '' NOT NULL,
	post_up text DEFAULT '' NOT NULL,
	pre_down text DEFAULT '' NOT NULL,
	post_down text DEFAULT '' NOT NULL,
	private_key text NOT NULL,
	public_key text NOT NULL,
	pre_shared_key text NOT NULL,
	expires_at text,
	allowed_ips text,
	server_allowed_ips text NOT NULL,
	persistent_keepalive integer NOT NULL,
	mtu integer NOT NULL,
	dns text,
	server_endpoint text,
	enabled integer NOT NULL,
	created_at text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	updated_at text DEFAULT (CURRENT_TIMESTAMP) NOT NULL,
	j_c integer, j_min integer, j_max integer,
	i1 text, i2 text, i3 text, i4 text, i5 text, firewall_ips text
);`

// easyClient — клиент базы-источника. Пустые dns/allowedIPs означают «взять умолчание интерфейса»,
// как это и записано у всех живых клиентов hel.
type easyClient struct {
	pair       wgkey.Pair
	name       string
	addr       string
	mtu        int
	keepalive  int
	dns        string
	allowedIPs string
	psk        string
	disabled   bool
	expires    string
}

const (
	easyDNS       = `["1.1.1.1"]`
	easyAllowed   = `["0.0.0.0/0","::/0"]`
	easyHost      = "vpn.example.com"
	easyPort      = 51820
	easyServerMTU = 1280
)

func makeWGEasySource(t *testing.T, serverPub, iface string, clients []easyClient) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wg-easy.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(wgEasySchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO interfaces_table (name, device, port, private_key, public_key, ipv4_cidr, ipv6_cidr, mtu, enabled)
		VALUES (?, 'eth0', ?, 'PRIVATEKEYPRIVATEKEYPRIVATEKEYPRIVATEKEYKEY=', ?, '10.8.0.0/24', 'fdcc::/112', ?, 1)`,
		iface, easyPort, serverPub, easyServerMTU); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO user_configs_table (id, default_mtu, default_persistent_keepalive, default_dns, default_allowed_ips, host, port)
		VALUES (?, ?, 25, ?, ?, ?, ?)`, iface, easyServerMTU, easyDNS, easyAllowed, easyHost, easyPort); err != nil {
		t.Fatal(err)
	}
	for _, c := range clients {
		enabled := 1
		if c.disabled {
			enabled = 0
		}
		var dns, allowed, expires any
		if c.dns != "" {
			dns = c.dns
		}
		if c.allowedIPs != "" {
			allowed = c.allowedIPs
		}
		if c.expires != "" {
			expires = c.expires
		}
		if _, err := db.Exec(`INSERT INTO clients_table (user_id, interface_id, name, ipv4_address, ipv6_address, private_key, public_key,
			pre_shared_key, expires_at, allowed_ips, server_allowed_ips, persistent_keepalive, mtu, dns, enabled)
			VALUES (1, ?, ?, ?, 'fdcc::cafe:2/112', ?, ?, ?, ?, ?, '[]', ?, ?, ?, ?)`,
			iface, c.name, c.addr, c.pair.Private, c.pair.Public, c.psk, expires, allowed, c.keepalive, c.mtu, dns, enabled); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

// openWGEasyHub — хаб с интерфейсом по образцу hel: MTU сервера 1280, умолчания ещё из миграции.
func openWGEasyHub(t *testing.T, serverPub string) (*store.Store, store.Interface) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	ctx := context.Background()
	srv, err := st.UpsertLocalServer(ctx, "hub", "Хаб")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.UpsertInterface(ctx, srv, "awg-new", store.InterfaceFacts{
		Subnet: "10.8.0.0/24", ServerAddress: "10.8.0.1/24", ListenPort: easyPort, MTU: easyServerMTU, IsAWG: true,
		ServerPublicKey: serverPub,
		Obfuscation:     map[string]string{"Jc": "4", "Jmin": "10", "Jmax": "50", "S1": "35", "S2": "22", "S3": "13", "S4": "17", "H1": "555555555", "H2": "666666666", "H3": "777777777", "H4": "888888888", "I1": "<r 2><b 0x8580>"},
	}); err != nil {
		t.Fatal(err)
	}
	list, err := st.Interfaces(ctx, srv)
	if err != nil || len(list) != 1 {
		t.Fatalf("interfaces = %+v, err = %v", list, err)
	}
	return st, list[0]
}

// sampleEasyClients — набор по образцу hel: у одного человека два устройства, у другого одно,
// имя из одного слова, повышенный MTU у всех и один выключенный клиент.
func sampleEasyClients(t *testing.T) []easyClient {
	t.Helper()
	specs := []struct {
		name     string
		mtu      int
		disabled bool
	}{
		{name: "Ivan.Petrov n1", mtu: 1376},
		{name: "Ivan.Petrov n2", mtu: 1376},
		{name: "Maria.Ivanova Phone", mtu: 1376},
		{name: "Maria.Ivanova Laptop", mtu: 1376, disabled: true},
		{name: "_ME Router", mtu: 1376},
		{name: "Solo", mtu: easyServerMTU},
	}
	out := make([]easyClient, 0, len(specs))
	for i, s := range specs {
		pair, err := wgkey.Generate()
		if err != nil {
			t.Fatal(err)
		}
		psk, err := wgkey.PSK()
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, easyClient{pair: pair, name: s.name, addr: fmt.Sprintf("10.8.0.%d", i+2),
			mtu: s.mtu, keepalive: 25, psk: psk, disabled: s.disabled})
	}
	return out
}

func TestWGEasyGroupsOwnersByFirstWord(t *testing.T) {
	ctx := context.Background()
	serverPair, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	st, iface := openWGEasyHub(t, serverPair.Public)
	clients := sampleEasyClients(t)
	src := makeWGEasySource(t, serverPair.Public, "wg0", clients)

	rep, err := WGEasy(ctx, st, iface, WGEasyOptions{DBPath: src})
	if err != nil {
		t.Fatalf("импорт: %v", err)
	}
	if rep.Total != len(clients) || len(rep.Created) != len(clients) {
		t.Fatalf("создано %d из %d, ожидалось %d: %s", len(rep.Created), rep.Total, len(clients), rep.String())
	}
	// Четыре владельца: два человека с несколькими устройствами, «_ME» и имя из одного слова.
	want := map[string][]string{
		"Ivan.Petrov":   {"n1", "n2"},
		"Maria.Ivanova": {"Laptop", "Phone"},
		"_ME":           {"Router"},
		"Solo":          {"Solo"},
	}
	if len(rep.CreatedUsers) != len(want) {
		t.Fatalf("заведено пользователей %v, ожидалось %d", rep.CreatedUsers, len(want))
	}
	for owner, devices := range want {
		u, err := st.UserByName(ctx, owner)
		if err != nil {
			t.Fatalf("пользователь %q: %v", owner, err)
		}
		got, err := st.DevicesByUser(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, d := range got {
			names = append(names, d.Name)
		}
		if strings.Join(sortedCopy(names), ", ") != strings.Join(devices, ", ") {
			t.Errorf("устройства %q: %v, ожидалось %v", owner, names, devices)
		}
	}
}

func TestWGEasyIssuedConfigMatchesSource(t *testing.T) {
	ctx := context.Background()
	serverPair, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	st, iface := openWGEasyHub(t, serverPair.Public)
	clients := sampleEasyClients(t)
	src := makeWGEasySource(t, serverPair.Public, "wg0", clients)
	if _, err := WGEasy(ctx, st, iface, WGEasyOptions{DBPath: src}); err != nil {
		t.Fatalf("импорт: %v", err)
	}
	// Умолчания и endpoint должны приехать из источника: иначе перевыдача даст человеку другой файл.
	list, err := st.Interfaces(ctx, iface.ServerID)
	if err != nil || len(list) != 1 {
		t.Fatalf("interfaces = %+v, err = %v", list, err)
	}
	fresh := list[0]
	if fresh.DefaultDNS != "1.1.1.1" || fresh.DefaultKeepalive != 25 || fresh.DefaultAllowedIPs != "0.0.0.0/0, ::/0" {
		t.Fatalf("умолчания интерфейса: DNS %q, keepalive %d, AllowedIPs %q", fresh.DefaultDNS, fresh.DefaultKeepalive, fresh.DefaultAllowedIPs)
	}
	if len(fresh.Endpoints) != 1 || fresh.Endpoints[0].Host != easyHost || fresh.Endpoints[0].Port != easyPort {
		t.Fatalf("endpoint интерфейса: %+v", fresh.Endpoints)
	}

	dev, err := st.DeviceByPublicKey(ctx, fresh.ID, clients[0].pair.Public)
	if err != nil {
		t.Fatal(err)
	}
	conf, err := clientconf.Build(fresh, dev, fresh.Endpoints[0])
	if err != nil {
		t.Fatal(err)
	}
	kv := configKV(conf)
	for key, want := range map[string]string{
		"Interface.DNS":            "1.1.1.1",
		"Interface.MTU":            "1376", // прописан каждому клиенту wg-easy и обязан пережить переезд
		"Interface.Address":        "10.8.0.2/32",
		"Interface.PrivateKey":     clients[0].pair.Private,
		"Peer.AllowedIPs":          "0.0.0.0/0, ::/0",
		"Peer.Endpoint":            easyHost + ":" + fmt.Sprint(easyPort),
		"Peer.PersistentKeepalive": "25",
		"Peer.PublicKey":           serverPair.Public,
		"Peer.PresharedKey":        clients[0].psk,
	} {
		if kv[key] != want {
			t.Errorf("%s = %q, ожидалось %q", key, kv[key], want)
		}
	}
	// Обфускация выдаётся из интерфейса целиком, включая S3/S4 и I1 в формате wg-easy.
	if kv["Interface.S3"] != "13" || kv["Interface.S4"] != "17" || !strings.HasPrefix(kv["Interface.I1"], "<r 2>") {
		t.Errorf("обфускация в конфиге: S3 %q, S4 %q, I1 %q", kv["Interface.S3"], kv["Interface.S4"], kv["Interface.I1"])
	}
	// MTU у клиента с серверным значением переопределением не становится.
	solo, err := st.DeviceByPublicKey(ctx, fresh.ID, clients[len(clients)-1].pair.Public)
	if err != nil {
		t.Fatal(err)
	}
	if solo.Overrides != (store.Overrides{}) {
		t.Errorf("устройство с умолчаниями получило переопределения: %+v", solo.Overrides)
	}
}

func TestWGEasyKeepsDisabledClientDisabled(t *testing.T) {
	ctx := context.Background()
	serverPair, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	st, iface := openWGEasyHub(t, serverPair.Public)
	clients := sampleEasyClients(t)
	src := makeWGEasySource(t, serverPair.Public, "wg0", clients)
	if _, err := WGEasy(ctx, st, iface, WGEasyOptions{DBPath: src}); err != nil {
		t.Fatalf("импорт: %v", err)
	}
	for _, c := range clients {
		dev, err := st.DeviceByPublicKey(ctx, iface.ID, c.pair.Public)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if c.disabled && dev.Active() {
			t.Errorf("%s: выключенный в wg-easy клиент импортирован активным", c.name)
		}
		if !c.disabled && !dev.Active() {
			t.Errorf("%s: включённый клиент импортирован выключенным", c.name)
		}
	}
}

func TestWGEasyRejectsDatabaseOfAnotherServer(t *testing.T) {
	ctx := context.Background()
	mine, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	other, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	st, iface := openWGEasyHub(t, mine.Public)
	src := makeWGEasySource(t, other.Public, "wg0", sampleEasyClients(t))
	_, err = WGEasy(ctx, st, iface, WGEasyOptions{DBPath: src})
	if err == nil || !strings.Contains(err.Error(), "другого сервера") {
		t.Fatalf("ожидался отказ импортировать чужую базу, получено: %v", err)
	}
	devices, err := st.DevicesByInterface(ctx, iface.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 0 {
		t.Fatalf("после отказа заведено %d устройств", len(devices))
	}
}

func TestWGEasyDryRunWritesNothing(t *testing.T) {
	ctx := context.Background()
	serverPair, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	st, iface := openWGEasyHub(t, serverPair.Public)
	clients := sampleEasyClients(t)
	src := makeWGEasySource(t, serverPair.Public, "wg0", clients)

	rep, err := WGEasy(ctx, st, iface, WGEasyOptions{DBPath: src, DryRun: true})
	if err != nil {
		t.Fatalf("примерка: %v", err)
	}
	if len(rep.Created) != len(clients) {
		t.Fatalf("примерка обещала %d из %d", len(rep.Created), len(clients))
	}
	devices, err := st.DevicesByInterface(ctx, iface.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != 0 {
		t.Fatalf("примерка завела %d устройств", len(devices))
	}
	list, err := st.Interfaces(ctx, iface.ServerID)
	if err != nil {
		t.Fatal(err)
	}
	if list[0].DefaultDNS != iface.DefaultDNS || len(list[0].Endpoints) != 0 {
		t.Fatalf("примерка изменила интерфейс: DNS %q, endpoints %+v", list[0].DefaultDNS, list[0].Endpoints)
	}
}

func TestWGEasyIsIdempotent(t *testing.T) {
	ctx := context.Background()
	serverPair, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	st, iface := openWGEasyHub(t, serverPair.Public)
	clients := sampleEasyClients(t)
	src := makeWGEasySource(t, serverPair.Public, "wg0", clients)
	if _, err := WGEasy(ctx, st, iface, WGEasyOptions{DBPath: src}); err != nil {
		t.Fatalf("первый импорт: %v", err)
	}
	list, _ := st.Interfaces(ctx, iface.ServerID)
	rep, err := WGEasy(ctx, st, list[0], WGEasyOptions{DBPath: src})
	if err != nil {
		t.Fatalf("повторный импорт: %v", err)
	}
	if len(rep.Created) != 0 || len(rep.Updated) != 0 || len(rep.Unchanged) != len(clients) {
		t.Fatalf("повтор изменил парк: %s", rep.String())
	}
	users, err := st.UserByName(ctx, "Ivan.Petrov")
	if err != nil {
		t.Fatal(err)
	}
	got, err := st.DevicesByUser(ctx, users.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("после повтора у владельца %d устройств, ожидалось 2", len(got))
	}
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// TestWGEasyLiveDatabase — сверка с настоящей базой wg-easy. Пропускается, пока не задан
// AWGDASH_WGEASY_DB: базу с приватными ключами не уносят с сервера, тест собирается
// кросс-сборкой и запускается там же (`go test -c ./internal/importer`).
func TestWGEasyLiveDatabase(t *testing.T) {
	path := os.Getenv("AWGDASH_WGEASY_DB")
	if path == "" {
		t.Skip("AWGDASH_WGEASY_DB не задан — живая сверка пропущена")
	}
	ctx := context.Background()
	serverPub, err := livePublicKey(path)
	if err != nil {
		t.Fatalf("ключ сервера из базы: %v", err)
	}
	st, iface := openWGEasyHub(t, serverPub)

	rep, err := WGEasy(ctx, st, iface, WGEasyOptions{DBPath: path, DryRun: true})
	if err != nil {
		t.Fatalf("примерка: %v", err)
	}
	t.Logf("примерка: %s", rep.String())
	if rep.Total == 0 {
		t.Fatal("в базе нет клиентов")
	}
	if len(rep.Skipped) > 0 {
		t.Fatalf("пропущено %d записей: %v", len(rep.Skipped), rep.Skipped)
	}

	if _, err := WGEasy(ctx, st, iface, WGEasyOptions{DBPath: path}); err != nil {
		t.Fatalf("импорт: %v", err)
	}
	list, err := st.Interfaces(ctx, iface.ServerID)
	if err != nil {
		t.Fatal(err)
	}
	fresh := list[0]
	devices, err := st.DevicesByInterface(ctx, fresh.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(devices) != rep.Total {
		t.Fatalf("заведено %d устройств из %d", len(devices), rep.Total)
	}
	owners, withMTU, disabled := map[string]int{}, 0, 0
	for _, d := range devices {
		full, err := st.DeviceByID(ctx, d.ID)
		if err != nil {
			t.Fatal(err)
		}
		owners[full.UserName]++
		if full.Overrides.MTU > 0 {
			withMTU++
		}
		if !full.Active() {
			disabled++
		}
		if full.PrivateKey == "" {
			t.Errorf("%s: устройство импортировано без приватного ключа", full.Name)
		}
		if _, err := clientconf.Build(fresh, full, fresh.Endpoints[0]); err != nil {
			t.Errorf("%s: конфиг не собирается: %v", full.Name, err)
		}
	}
	t.Logf("владельцев: %d, устройств: %d, с переопределением MTU: %d, выключенных: %d",
		len(owners), len(devices), withMTU, disabled)
	t.Logf("умолчания интерфейса: DNS %q, keepalive %d, AllowedIPs %q, endpoint %+v",
		fresh.DefaultDNS, fresh.DefaultKeepalive, fresh.DefaultAllowedIPs, fresh.Endpoints)

	again, err := WGEasy(ctx, st, fresh, WGEasyOptions{DBPath: path})
	if err != nil {
		t.Fatalf("повторный импорт: %v", err)
	}
	if len(again.Created) != 0 || len(again.Updated) != 0 {
		t.Fatalf("повтор изменил парк: создано %d, обновлено %d", len(again.Created), len(again.Updated))
	}
}

// livePublicKey читает публичный ключ сервера из базы источника: живая сверка не должна
// требовать, чтобы ключ был вписан в тест.
func livePublicKey(path string) (string, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return "", err
	}
	defer db.Close()
	var pub string
	err = db.QueryRow(`SELECT COALESCE(public_key, '') FROM interfaces_table ORDER BY name LIMIT 1`).Scan(&pub)
	return pub, err
}
