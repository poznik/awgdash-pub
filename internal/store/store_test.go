package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestMigrateAndServers(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	id, err := s.UpsertLocalServer(ctx, "de", "Германия")
	if err != nil || id == 0 {
		t.Fatal(err)
	}
	id2, _ := s.UpsertLocalServer(ctx, "de", "Германия · de")
	if id2 != id {
		t.Fatal("upsert создал второй сервер")
	}
	// Имя, заданное человеком, при повторном старте не затирается — проверяем именно это.
	if srv, _ := s.ServerBySlug(ctx, "de"); srv.Title != "Германия" {
		t.Fatalf("имя стало %q, ожидалось прежнее «Германия»", srv.Title)
	}
	if err := s.TouchServer(ctx, id, "203.0.113.10", "eth0", "6.8.0", "v3", "dev", true); err != nil {
		t.Fatal(err)
	}
	srv, _ := s.Servers(ctx)
	if len(srv) != 1 || srv[0].Title != "Германия" || !srv[0].RebootRequired || srv[0].PublicIP != "203.0.113.10" {
		t.Fatalf("servers = %+v", srv)
	}
	// Повторное открытие — миграции идемпотентны.
	s2, err := Open(filepath.Join(t.TempDir(), "t2.db"))
	if err != nil {
		t.Fatal(err)
	}
	s2.Close()
}

func TestApplySampleDeltasAndResets(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	srv, _ := s.UpsertLocalServer(ctx, "de", "de")
	iface, err := s.UpsertInterface(ctx, srv, "awg-old", InterfaceFacts{Subnet: "10.20.0.0/16", ListenPort: 443, IsAWG: true, Obfuscation: map[string]string{"Jc": "6"}})
	if err != nil {
		t.Fatal(err)
	}
	t0 := time.Unix(1_800_000_000, 0)
	a := PeerSample{PublicKey: "A", AllowedIPs: "10.20.0.2/32", Rx: 1000, Tx: 500, LastHandshake: t0.Add(-10 * time.Second), Endpoint: "1.2.3.4:5"}
	b := PeerSample{PublicKey: "B", AllowedIPs: "10.20.0.3/32", Rx: 0, Tx: 0}
	r, err := s.ApplySample(ctx, iface, t0, []PeerSample{a, b}, 180*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if r.Peers != 2 || r.NewPeers != 2 || r.Rows != 0 || r.Online != 1 {
		t.Fatalf("первая выборка: %+v", r)
	}
	// Вторая выборка: A вырос, B без изменений.
	a.Rx, a.Tx = 1600, 700
	r, _ = s.ApplySample(ctx, iface, t0.Add(15*time.Second), []PeerSample{a, b}, 180*time.Second)
	if r.Rows != 1 || r.NewPeers != 0 {
		t.Fatalf("вторая выборка: %+v", r)
	}
	// Третья: сброс счётчиков у A (рестарт интерфейса) — дельта считается от нуля; B исчез.
	a.Rx, a.Tx = 300, 100
	r, _ = s.ApplySample(ctx, iface, t0.Add(30*time.Second), []PeerSample{a}, 180*time.Second)
	if r.Resets != 1 || r.Rows != 1 {
		t.Fatalf("третья выборка: %+v", r)
	}
	peers, err := s.Peers(ctx, iface, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 2 {
		t.Fatalf("peers = %d", len(peers))
	}
	var pa, pb PeerRow
	for _, p := range peers {
		if p.PublicKey == "A" {
			pa = p
		} else {
			pb = p
		}
	}
	if pa.RxTotal != 600+300 || pa.TxTotal != 200+100 || pa.Endpoint != "1.2.3.4:5" || pa.LastHandshake.IsZero() {
		t.Fatalf("A = %+v", pa)
	}
	if pb.RemovedAt.IsZero() {
		t.Fatal("B не помечен исчезнувшим")
	}
	// B вернулся — removed_at снят, счётчики с нуля не дают ложной дельты (0 → 0).
	r, _ = s.ApplySample(ctx, iface, t0.Add(45*time.Second), []PeerSample{a, b}, 180*time.Second)
	peers, _ = s.Peers(ctx, iface, false)
	if len(peers) != 2 {
		t.Fatalf("после возврата B: %d", len(peers))
	}
	// Агрегаты и ретеншн не падают на данных.
	if err := s.Rollup(ctx, 2*time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := s.Retention(ctx, 48*time.Hour, 90*24*time.Hour); err != nil {
		t.Fatal(err)
	}
	ts, rx, _, err := s.TrafficSeries(ctx, iface, t0.Add(-time.Minute), time.Minute)
	if err != nil || len(ts) == 0 || rx[0] == 0 {
		t.Fatalf("series: %v %v %v", err, ts, rx)
	}
}

func TestEventsAndSettings(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	if err := s.AddEvent(ctx, Event{Kind: "panel_started", Message: "старт"}); err != nil {
		t.Fatal(err)
	}
	ev, _ := s.Events(ctx, 10)
	if len(ev) != 1 || ev[0].Kind != "panel_started" || ev[0].Severity != "info" {
		t.Fatalf("events = %+v", ev)
	}
	s.SetSetting(ctx, "k", "v")
	s.SetSetting(ctx, "k", "w")
	if v, _ := s.Setting(ctx, "k"); v != "w" {
		t.Fatalf("setting = %q", v)
	}
	if v, _ := s.Setting(ctx, "нет"); v != "" {
		t.Fatal("несуществующая настройка не пуста")
	}
}

// Флаг сервера рисуется из кода страны, а при его отсутствии — угадывается по слагу.
func TestServerFlag(t *testing.T) {
	cases := []struct{ slug, country, want string }{
		{"de", "", "🇩🇪"},
		{"kz", "", "🇰🇿"},
		{"de", "NL", "🇳🇱"},     // задан явно — он и побеждает
		{"hetzner-1", "", ""},  // слаг не похож на код страны
		{"de", "не код", "🇩🇪"}, // мусор в коде — возвращаемся к догадке
	}
	for _, c := range cases {
		got := Server{Slug: c.slug, Country: c.country}.Flag()
		if got != c.want {
			t.Fatalf("слаг %q, код %q → %q, ожидалось %q", c.slug, c.country, got, c.want)
		}
	}
}

// Имя сервера, заданное человеком, переживает перезапуск панели.
func TestUpsertLocalServerKeepsTitle(t *testing.T) {
	s := openTest(t)
	ctx := t.Context()
	id, err := s.UpsertLocalServer(ctx, "de", "de")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetServerTitle(ctx, id, "Германия"); err != nil {
		t.Fatal(err)
	}
	// Повторный старт панели: слаг тот же, имя из конфига прежнее.
	if _, err := s.UpsertLocalServer(ctx, "de", "de"); err != nil {
		t.Fatal(err)
	}
	srv, err := s.ServerBySlug(ctx, "de")
	if err != nil {
		t.Fatal(err)
	}
	if srv.Title != "Германия" {
		t.Fatalf("имя сервера стало %q — перезапуск затёр заданное", srv.Title)
	}
}

// Умолчания клиентского конфига правятся из панели, поэтому проверка живёт в хранилище: имя
// резолвера в строке DNS клиент AmneziaWG молча не примет, а увидит это человек уже у себя.
func TestSetInterfaceDefaultsValidates(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	srvID, err := s.UpsertLocalServer(ctx, "de", "Германия")
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.UpsertInterface(ctx, srvID, "awg-t0", InterfaceFacts{Subnet: "10.20.0.0/16", ListenPort: 443, IsAWG: true})
	if err != nil {
		t.Fatal(err)
	}

	// IPv4, IPv6 и лишние пробелы — законный список; он приводится к общему виду.
	if err := s.SetInterfaceDefaults(ctx, id, " 10.40.0.1,2606:4700:4700::1111 ", 25, "0.0.0.0/0,::/0"); err != nil {
		t.Fatal(err)
	}
	list, _ := s.Interfaces(ctx, srvID)
	if got := list[0].DefaultDNS; got != "10.40.0.1, 2606:4700:4700::1111" {
		t.Fatalf("DNS сохранён как %q", got)
	}
	if got := list[0].DefaultAllowedIPs; got != "0.0.0.0/0, ::/0" {
		t.Fatalf("AllowedIPs сохранён как %q", got)
	}
	// Пустой DNS законен: строки DNS в конфиге тогда не будет.
	if err := s.SetInterfaceDefaults(ctx, id, "", 0, "0.0.0.0/0"); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name       string
		dns        string
		keepalive  int
		allowedIPs string
	}{
		{"имя вместо адреса", "dns.дома", 25, "0.0.0.0/0"},
		{"подсеть вместо адреса", "10.40.0.0/24", 25, "0.0.0.0/0"},
		{"пустой AllowedIPs", "10.40.0.1", 25, " , "},
		{"keepalive вне диапазона", "10.40.0.1", 70000, "0.0.0.0/0"},
	} {
		if err := s.SetInterfaceDefaults(ctx, id, c.dns, c.keepalive, c.allowedIPs); err == nil {
			t.Fatalf("%s: принято без ошибки", c.name)
		}
	}
	if list, _ = s.Interfaces(ctx, srvID); list[0].DefaultDNS != "" || list[0].DefaultAllowedIPs != "0.0.0.0/0" {
		t.Fatalf("отказ всё же изменил умолчания: %q %q", list[0].DefaultDNS, list[0].DefaultAllowedIPs)
	}
}
