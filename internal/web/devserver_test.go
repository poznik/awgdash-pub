//go:build devserver

// Стенд для осмотра UI: поднимает панель с синтетикой и держит её, пока не убьют.
// Запуск: go test ./internal/web -tags devserver -run TestDevServer -timeout 60m -v
package web

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/poznik/awgdash-pub/internal/store"
	"github.com/poznik/awgdash-pub/internal/wgkey"
)

func TestDevServer(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	db := e.store.DB()
	now := time.Now()
	rnd := rand.New(rand.NewSource(7))

	// --- сервер de: факты + режим own
	if _, err := db.ExecContext(ctx, `UPDATE servers SET public_ip='203.0.113.44', kernel='6.8.0-45-generic',
		awg_version='3.0.20260805', awgdash_version='0.9.0', last_seen_at=?, country='DE', title='Германия' WHERE slug='de'`, now.Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE interfaces SET mode='own', unit_active=1, last_verified_at=?, last_verify_ok=1,
		default_dns='1.1.1.1, 8.8.8.8', default_keepalive=21 WHERE name='awg-t0'`, now.Add(-2*time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	deID := e.iface.ID
	var deSrv int64
	db.QueryRowContext(ctx, `SELECT id FROM servers WHERE slug='de'`).Scan(&deSrv)

	// --- сервер kz
	kz, err := e.store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", SSHHost: "node2.example.com", NodePort: 10089, Country: "KZ"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE servers SET public_ip='198.51.100.9', kernel='6.8.0-45-generic',
		awg_version='3.0.20260805', awgdash_version='0.9.0', last_seen_at=?, reboot_required=1 WHERE id=?`, now.Add(-40*time.Second).Unix(), kz.ID); err != nil {
		t.Fatal(err)
	}
	kzIf, err := e.store.UpsertInterface(ctx, kz.ID, "awg-kz", store.InterfaceFacts{
		ConfPath: "/etc/amnezia/amneziawg/awg-kz.conf", Subnet: "10.30.0.0/24", ServerAddress: "10.30.0.1/24",
		ListenPort: 443, MTU: 1280, IsAWG: true, UnitActive: true, ServerPublicKey: "KZSERVERPUB=",
		Obfuscation: map[string]string{"Jc": "4", "I1": "<b 0x01>"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE interfaces SET mode='own', last_verified_at=?, last_verify_ok=1 WHERE id=?`, now.Add(-3*time.Minute).Unix(), kzIf); err != nil {
		t.Fatal(err)
	}

	// --- люди и устройства
	type spec struct {
		name, note string
		devices    []string
		iface      int64
		self       bool
		status     string
		expires    time.Duration
		idle       []time.Duration // сколько назад хендшейк у каждого устройства; -1 — не подключался
		idleRaw    []time.Duration
	}
	people := []spec{
		{name: "Ирина", note: "сестра", devices: []string{"iPhone Ирины", "Ноутбук"}, self: true, idleRaw: []time.Duration{40 * time.Second, 3 * time.Hour}},
		{name: "Павел", note: "коллега", devices: []string{"Pixel", "MacBook", "Роутер дома"}, idleRaw: []time.Duration{25 * time.Second, 90 * time.Second, 12 * time.Minute}},
		{name: "Мама", devices: []string{"Планшет"}, idleRaw: []time.Duration{6 * 24 * time.Hour}},
		{name: "Дмитрий", note: "работа", devices: []string{"Рабочий ноут", "Телефон"}, self: true, idleRaw: []time.Duration{50 * time.Second, 4 * 24 * time.Hour}},
		{name: "Анна", devices: []string{"iPad", "iPhone"}, iface: 1, idleRaw: []time.Duration{70 * time.Second, 30 * time.Minute}},
		{name: "Сергей", note: "приятель", devices: []string{"Xiaomi"}, status: "disabled", idleRaw: []time.Duration{2 * 24 * time.Hour}},
		{name: "Оля", devices: []string{"Телефон", "Ноутбук"}, expires: 5 * 24 * time.Hour, idleRaw: []time.Duration{35 * time.Second, -1}},
		{name: "Без владельца", note: "импорт из WGDashboard", devices: []string{"peer-3", "peer-5"}, idleRaw: []time.Duration{9 * time.Minute, -1}},
		{name: "Кирилл", devices: []string{"Телефон"}, iface: 1, idleRaw: []time.Duration{45 * time.Second}},
		{name: "Гости", note: "временный доступ", devices: []string{"Ноутбук гостя"}, expires: -2 * 24 * time.Hour, idleRaw: []time.Duration{20 * 24 * time.Hour}},
	}

	addr := map[int64]int{deID: 2, kzIf: 2}
	var peerIDs []int64
	for _, p := range people {
		u := store.User{Name: p.name, Note: p.note, SelfService: p.self, MaxDevices: 5, DefaultInterfaceID: deID, Status: "active"}
		if p.status != "" {
			u.Status = p.status
		}
		if p.expires != 0 {
			u.ExpiresAt = now.Add(p.expires)
		}
		uid, _, err := e.store.CreateUser(ctx, u)
		if err != nil {
			t.Fatal(err)
		}
		ifID := deID
		if p.iface == 1 {
			ifID = kzIf
		}
		for i, dn := range p.devices {
			pair, _ := wgkey.Generate()
			preset := store.PresetPhone
			if dn == "Роутер дома" {
				preset = store.PresetRouter
			}
			addr[ifID]++
			var ip string
			if ifID == deID {
				ip = fmt.Sprintf("10.20.0.%d/32", addr[ifID])
			} else {
				ip = fmt.Sprintf("10.30.0.%d/32", addr[ifID])
			}
			did, err := e.store.CreateDevice(ctx, store.Device{UserID: uid, InterfaceID: ifID, Name: dn, Preset: preset,
				PrivateKey: pair.Private, PublicKey: pair.Public, Address: ip, Status: "active"})
			if err != nil {
				t.Fatal(err)
			}
			// пир в рантайме + его состояние
			res, err := db.ExecContext(ctx, `INSERT INTO peers (interface_id, public_key, allowed_ips, has_psk, device_id, in_conf, first_seen_at, last_seen_at)
				VALUES (?, ?, ?, 1, ?, 1, ?, ?)`, ifID, pair.Public, ip, did, now.Add(-30*24*time.Hour).Unix(), now.Unix())
			if err != nil {
				t.Fatal(err)
			}
			pid, _ := res.LastInsertId()
			peerIDs = append(peerIDs, pid)
			hs := int64(0)
			idle := 24 * time.Hour
			if i < len(p.idleRaw) && p.idleRaw[i] >= 0 {
				idle = p.idleRaw[i]
				hs = now.Add(-idle).Unix()
			}
			// Клиент скачивает больше, чем отдаёт: tx сервера (то, что человек скачал) крупный,
			// rx — в несколько раз меньше. На живом парке это отношение примерно 13 к 1.
			tx := uint64(rnd.Int63n(80_000_000_000)) + 1_000_000_000
			rx := tx / uint64(3+rnd.Intn(6))
			if _, err := db.ExecContext(ctx, `INSERT INTO peer_state (peer_id, rx_counter, tx_counter, last_handshake, first_handshake_at, endpoint, sampled_at, rx_total, tx_total)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`, pid, rx, tx, hs, now.Add(-30*24*time.Hour).Unix(),
				fmt.Sprintf("176.59.%d.%d:%d", rnd.Intn(250), rnd.Intn(250), 30000+rnd.Intn(20000)), now.Unix(), rx, tx); err != nil {
				t.Fatal(err)
			}
			// сырой трафик за сутки: минутные записи, активность днём
			if hs != 0 && idle < 48*time.Hour {
				stmt := `INSERT INTO traffic_raw (ts, peer_id, rx, tx) VALUES (?, ?, ?, ?)`
				for m := 0; m < 1440; m++ {
					ts := now.Add(-time.Duration(1440-m) * time.Minute).Truncate(time.Minute).Unix()
					if now.Sub(time.Unix(ts, 0)) < idle {
						continue
					}
					hour := time.Unix(ts, 0).Hour()
					day := 0.35 + 0.65*math.Max(0, math.Sin(float64(hour-4)/24*math.Pi))
					if rnd.Float64() < 0.25 {
						continue
					}
					down := uint64(day * float64(200_000+rnd.Int63n(4_000_000)))
					if _, err := db.ExecContext(ctx, stmt, ts, pid, down/uint64(4+rnd.Intn(5)), down); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}

	// один «ничей» пир на de — чтобы был виден сценарий привязки
	orphan, _ := wgkey.Generate()
	res, _ := db.ExecContext(ctx, `INSERT INTO peers (interface_id, public_key, allowed_ips, has_psk, in_conf, first_seen_at, last_seen_at)
		VALUES (?, ?, '10.20.0.77/32', 0, 1, ?, ?)`, deID, orphan.Public, now.Add(-100*24*time.Hour).Unix(), now.Unix())
	oid, _ := res.LastInsertId()
	db.ExecContext(ctx, `INSERT INTO peer_state (peer_id, last_handshake, sampled_at, rx_total, tx_total) VALUES (?, ?, ?, 12000000000, 900000000)`,
		oid, now.Add(-11*time.Minute).Unix(), now.Unix())

	// удалённый пользователь — корзина
	tid, _, _ := e.store.CreateUser(ctx, store.User{Name: "Тимур", Note: "уехал", MaxDevices: 5, DefaultInterfaceID: deID, Status: "active"})
	e.store.DeleteUser(ctx, tid)

	// Агрегаты из тех же сырых записей: суточный график читает пятиминутки, а парковый и
	// месячный — часы. Без них стенд показывал «данных пока нет» на всех графиках сразу.
	for _, q := range []string{
		`INSERT OR REPLACE INTO traffic_5m (bucket, peer_id, rx, tx) SELECT ts - ts % 300, peer_id, SUM(rx), SUM(tx) FROM traffic_raw GROUP BY 1, 2`,
		`INSERT OR REPLACE INTO traffic_1h (bucket, peer_id, rx, tx) SELECT ts - ts % 3600, peer_id, SUM(rx), SUM(tx) FROM traffic_raw GROUP BY 1, 2`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}

	// --- метрики хоста за сутки (с провалом «панель не работала»)
	for _, s := range []struct {
		id            int64
		cpu, mem, dsk float64
	}{{deSrv, 7, 0.31, 0.48}, {kz.ID, 4, 0.22, 0.71}} {
		for m := 0; m < 1440; m++ {
			ts := now.Add(-time.Duration(1440-m) * time.Minute).Truncate(time.Minute).Unix()
			if m > 700 && m < 760 { // полчаса тишины
				continue
			}
			hour := time.Unix(ts, 0).Hour()
			day := 0.4 + 0.6*math.Max(0, math.Sin(float64(hour-4)/24*math.Pi))
			if _, err := db.ExecContext(ctx, `INSERT INTO host_metrics (server_id, ts, cpu, mem_used, mem_total, swap_used, swap_total,
				disk_used, disk_total, load1, net_rx_bps, net_tx_bps, net_rx_bytes, net_tx_bytes, peers_online)
				VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				s.id, ts, s.cpu*day+rnd.Float64()*3,
				int64(s.mem*2_000_000_000*(0.9+0.2*day)), int64(2_000_000_000), int64(120_000_000), int64(1_000_000_000),
				int64(s.dsk*40_000_000_000), int64(40_000_000_000), 0.12+day*0.5,
				int64(day*float64(3_000_000+rnd.Int63n(9_000_000))), int64(day*float64(600_000+rnd.Int63n(2_000_000))),
				int64(day*float64(90_000_000_000)), int64(day*float64(20_000_000_000)), 3+rnd.Intn(6)); err != nil {
				t.Fatal(err)
			}
		}
	}

	// --- события и журнал действий
	events := []struct {
		ago            time.Duration
		kind, sev, msg string
	}{
		{2 * time.Minute, "peer.first_connect", "info", "Ирина · iPhone Ирины подключился впервые"},
		{14 * time.Minute, "traffic.spike", "warn", "Павел · MacBook: 12 ГБ за час — втрое выше обычного"},
		{40 * time.Minute, "handshake.drought", "crit", "awg-kz: сутки были подключения, четверть часа тишины — похоже на блокировку адреса"},
		{2 * time.Hour, "self_service", "info", "Дмитрий добавил устройство «Телефон» из портала"},
		{5 * time.Hour, "disk.threshold", "warn", "kz: диск занят на 71 %"},
		{9 * time.Hour, "iface.reconcile", "info", "awg-t0: сверка без изменений, 14 пиров"},
		{18 * time.Hour, "node.down", "crit", "kz: узел не отвечал 4 минуты"},
		{26 * time.Hour, "hub.start", "info", "панель запущена, версия 0.9.0"},
	}
	for _, ev := range events {
		if err := e.store.AddEvent(ctx, store.Event{TS: now.Add(-ev.ago), Kind: ev.kind, Severity: ev.sev, Message: ev.msg, ServerID: deSrv}); err != nil {
			t.Fatal(err)
		}
	}
	audits := []struct {
		ago         time.Duration
		act, target string
	}{
		{3 * time.Minute, "device.create", "device"}, {28 * time.Minute, "user.link_reissue", "user"},
		{3 * time.Hour, "device.rotate", "device"}, {7 * time.Hour, "user.create", "user"},
		{22 * time.Hour, "iface.mode", "interface"}, {30 * time.Hour, "device.delete", "device"},
	}
	for i, a := range audits {
		e.store.AddAudit(ctx, store.AuditEntry{TS: now.Add(-a.ago), Actor: "admin", Action: a.act, TargetType: a.target,
			TargetID: int64(i + 1), IP: "192.168.1.20", Details: map[string]any{"name": "Телефон"}})
	}

	// AWGDASH_STAND_SEED=200 — замер бюджетов §7.1 на объёме приёмки: 200 пользователей × 3 устройства.
	if n := os.Getenv("AWGDASH_STAND_SEED"); n != "" {
		count := 0
		fmt.Sscanf(n, "%d", &count)
		for i := 0; i < count; i++ {
			uid, _, err := e.store.CreateUser(ctx, store.User{Name: fmt.Sprintf("Нагрузка %03d", i), MaxDevices: 5,
				DefaultInterfaceID: deID, Status: "active"})
			if err != nil {
				t.Fatal(err)
			}
			for k := 0; k < 3; k++ {
				pair, _ := wgkey.Generate()
				addr[deID]++
				did, err := e.store.CreateDevice(ctx, store.Device{UserID: uid, InterfaceID: deID,
					Name: fmt.Sprintf("Устройство %d", k+1), Preset: store.PresetPhone,
					PrivateKey: pair.Private, PublicKey: pair.Public,
					Address: fmt.Sprintf("10.20.%d.%d/32", addr[deID]/250+1, addr[deID]%250+2), Status: "active"})
				if err != nil {
					t.Fatal(err)
				}
				res, err := db.ExecContext(ctx, `INSERT INTO peers (interface_id, public_key, allowed_ips, has_psk, device_id, in_conf, first_seen_at, last_seen_at)
					VALUES (?, ?, '10.20.9.9/32', 1, ?, 1, ?, ?)`, deID, pair.Public, did, now.Add(-72*time.Hour).Unix(), now.Unix())
				if err != nil {
					t.Fatal(err)
				}
				pid, _ := res.LastInsertId()
				hs := now.Add(-time.Duration(rnd.Intn(3600)) * time.Second).Unix()
				db.ExecContext(ctx, `INSERT INTO peer_state (peer_id, rx_counter, tx_counter, last_handshake, sampled_at, rx_total, tx_total)
					VALUES (?, ?, ?, ?, ?, ?, ?)`, pid, rnd.Int63n(9e10), rnd.Int63n(2e10), hs, now.Unix(), rnd.Int63n(9e10), rnd.Int63n(2e10))
				// сутки пятиминуток — как после rollup на живом сервере
				for m := 0; m < 288; m++ {
					ts := now.Add(-time.Duration(288-m) * 5 * time.Minute).Unix()
					db.ExecContext(ctx, `INSERT OR REPLACE INTO traffic_5m (bucket, peer_id, rx, tx) VALUES (?, ?, ?, ?)`,
						ts-ts%300, pid, rnd.Int63n(4_000_000), rnd.Int63n(800_000))
				}
			}
		}
		fmt.Printf(">>> синтетика приёмки: %d пользователей × 3 устройства\n", count)
	}

	fmt.Printf("\n\n>>> СТЕНД: %s   логин admin / %s\n\n", e.srv.URL, testPassword)
	time.Sleep(45 * time.Minute)
}
