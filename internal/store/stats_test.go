package store

import (
	"context"
	"testing"
	"time"
)

// заполняет трафик по часам назад от текущего момента: h=1 — час назад.
func seedTraffic(t *testing.T, s *Store, peerID int64, hoursAgo int, rx, tx uint64) {
	t.Helper()
	ctx := context.Background()
	ts := time.Now().Add(-time.Duration(hoursAgo) * time.Hour).Unix()
	if _, err := s.DB().ExecContext(ctx, `INSERT OR REPLACE INTO traffic_raw (ts, peer_id, rx, tx) VALUES (?, ?, ?, ?)`,
		ts-ts%15, peerID, rx, tx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().ExecContext(ctx, `INSERT OR REPLACE INTO traffic_1h (bucket, peer_id, rx, tx) VALUES (?, ?, ?, ?)`,
		ts-ts%3600, peerID, rx, tx); err != nil {
		t.Fatal(err)
	}
}

func TestPeerTotals(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	user, _, _ := s.CreateUser(ctx, User{Name: "Анна"})
	devID, err := s.CreateDevice(ctx, Device{UserID: user, InterfaceID: iface.ID, Name: "Телефон", PublicKey: "PK", Address: "10.20.0.2"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := s.ApplySample(ctx, iface.ID, now, []PeerSample{{PublicKey: "PK", AllowedIPs: "10.20.0.2/32", Rx: 1000, Tx: 500}}, OnlineWindow); err != nil {
		t.Fatal(err)
	}
	peers, _ := s.PeerIDsOf(ctx, []int64{devID})
	if len(peers) != 1 {
		t.Fatalf("пиров устройства: %d", len(peers))
	}

	seedTraffic(t, s, peers[0], 2, 100, 50)      // сутки, неделя, месяц
	seedTraffic(t, s, peers[0], 3*24, 200, 100)  // неделя и месяц
	seedTraffic(t, s, peers[0], 20*24, 400, 200) // только месяц

	tot, err := s.PeerTotals(ctx, peers)
	if err != nil {
		t.Fatal(err)
	}
	if tot.DayRx != 100 || tot.DayTx != 50 {
		t.Fatalf("сутки: %d/%d", tot.DayRx, tot.DayTx)
	}
	if tot.WeekRx != 300 || tot.WeekTx != 150 {
		t.Fatalf("неделя: %d/%d", tot.WeekRx, tot.WeekTx)
	}
	if tot.MonthRx != 700 || tot.MonthTx != 350 {
		t.Fatalf("месяц: %d/%d", tot.MonthRx, tot.MonthTx)
	}
	// «Всё время» берётся из накопленных сумм пира, а не из ретеншируемых рядов.
	if _, err := s.ApplySample(ctx, iface.ID, now.Add(time.Minute), []PeerSample{{PublicKey: "PK", AllowedIPs: "10.20.0.2/32", Rx: 3000, Tx: 1500}}, OnlineWindow); err != nil {
		t.Fatal(err)
	}
	tot, _ = s.PeerTotals(ctx, peers)
	if tot.AllRx != 2000 || tot.AllTx != 1000 {
		t.Fatalf("всё время: %d/%d", tot.AllRx, tot.AllTx)
	}
	// Пустой набор — нули, а не ошибка.
	if tot, err := s.PeerTotals(ctx, nil); err != nil || tot.DayRx != 0 {
		t.Fatalf("пустой набор: %+v, err = %v", tot, err)
	}
}

func TestPeerSeriesMarksGaps(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	srv, _ := s.UpsertLocalServer(ctx, "de", "Германия")
	user, _, _ := s.CreateUser(ctx, User{Name: "Анна"})
	devID, _ := s.CreateDevice(ctx, Device{UserID: user, InterfaceID: iface.ID, Name: "Телефон", PublicKey: "PK", Address: "10.20.0.2"})
	if _, err := s.ApplySample(ctx, iface.ID, time.Now(), []PeerSample{{PublicKey: "PK", AllowedIPs: "10.20.0.2/32"}}, OnlineWindow); err != nil {
		t.Fatal(err)
	}
	peers, _ := s.PeerIDsOf(ctx, []int64{devID})

	// Панель работала два часа назад и сейчас, а час назад молчала.
	for _, hoursAgo := range []int{2, 0} {
		if err := s.InsertHostMetric(ctx, HostMetric{ServerID: srv, TS: time.Now().Add(-time.Duration(hoursAgo) * time.Hour), CPU: 1}); err != nil {
			t.Fatal(err)
		}
	}
	seedTraffic(t, s, peers[0], 2, 100, 50)

	points, err := s.PeerSeries(ctx, peers, srv, time.Now().Add(-3*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var withData, gaps int
	for _, p := range points {
		if p.Rx > 0 {
			withData++
		}
		if p.Gap {
			gaps++
		}
	}
	if withData != 1 {
		t.Fatalf("корзин с данными: %d", withData)
	}
	if gaps == 0 {
		t.Fatal("пропуск не отмечен — молчание панели выглядит как ноль трафика")
	}
	// Корзина, где панель работала, но трафика не было, пропуском не считается.
	for _, p := range points {
		if p.TS == time.Now().Unix()-time.Now().Unix()%3600 && p.Gap {
			t.Fatal("текущая корзина помечена пропуском, хотя панель работает")
		}
	}
}

func TestPeerSpeedAndGrowth(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	user, _, _ := s.CreateUser(ctx, User{Name: "Анна"})
	devID, _ := s.CreateDevice(ctx, Device{UserID: user, InterfaceID: iface.ID, Name: "Телефон", PublicKey: "PK", Address: "10.20.0.2"})
	if _, err := s.ApplySample(ctx, iface.ID, time.Now(), []PeerSample{{PublicKey: "PK", AllowedIPs: "10.20.0.2/32"}}, OnlineWindow); err != nil {
		t.Fatal(err)
	}
	peers, _ := s.PeerIDsOf(ctx, []int64{devID})

	ts := time.Now().Unix()
	for i := 0; i < 4; i++ { // 4 записи по 15 с внутри минуты
		if _, err := s.DB().ExecContext(ctx, `INSERT OR REPLACE INTO traffic_raw (ts, peer_id, rx, tx) VALUES (?, ?, ?, ?)`,
			ts-int64(i*15), peers[0], 15000, 3000); err != nil {
			t.Fatal(err)
		}
	}
	sp, err := s.PeerSpeed(ctx, peers, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// 60 000 байт за минуту — тысяча байт в секунду.
	if sp.RxBps != 1000 || sp.TxBps != 200 {
		t.Fatalf("скорость: %d/%d байт/с", sp.RxBps, sp.TxBps)
	}
	growth, err := s.PeerGrowth(ctx, peers, 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if growth[peers[0]] != 72000 {
		t.Fatalf("рост за пять минут: %d", growth[peers[0]])
	}
}

func TestPeerDays(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	user, _, _ := s.CreateUser(ctx, User{Name: "Анна"})
	devID, _ := s.CreateDevice(ctx, Device{UserID: user, InterfaceID: iface.ID, Name: "Телефон", PublicKey: "PK", Address: "10.20.0.2"})
	if _, err := s.ApplySample(ctx, iface.ID, time.Now(), []PeerSample{{PublicKey: "PK", AllowedIPs: "10.20.0.2/32"}}, OnlineWindow); err != nil {
		t.Fatal(err)
	}
	peers, _ := s.PeerIDsOf(ctx, []int64{devID})
	seedTraffic(t, s, peers[0], 1, 100, 10)
	seedTraffic(t, s, peers[0], 3, 200, 20)
	seedTraffic(t, s, peers[0], 30, 300, 30)

	days, err := s.PeerDays(ctx, peers, time.Now().Add(-7*24*time.Hour), time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if len(days) == 0 {
		t.Fatal("таблица по дням пуста")
	}
	// Свежие дни сверху.
	if len(days) > 1 && days[0].Date.Before(days[1].Date) {
		t.Fatal("порядок дней не от свежих к старым")
	}
	var total uint64
	for _, d := range days {
		total += d.Rx
	}
	if total != 600 {
		t.Fatalf("сумма по дням: %d, ожидалось 600", total)
	}
}

// Суточный график строится по сырым записям с получасовой корзиной. Пока источник выбирался
// только по глубине окна, «сутки» уходили в traffic_1h (now-24ч всегда чуть старше суток), часовые
// строки ложились в каждую вторую корзину и линия падала в ноль через полчаса.
func TestPeerSeriesDayKeepsHalfHourBuckets(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	srv, _ := s.UpsertLocalServer(ctx, "de", "Германия")
	user, _, _ := s.CreateUser(ctx, User{Name: "Анна"})
	devID, _ := s.CreateDevice(ctx, Device{UserID: user, InterfaceID: iface.ID, Name: "Телефон", PublicKey: "PK", Address: "10.20.0.2"})
	if _, err := s.ApplySample(ctx, iface.ID, time.Now(), []PeerSample{{PublicKey: "PK", AllowedIPs: "10.20.0.2/32"}}, OnlineWindow); err != nil {
		t.Fatal(err)
	}
	peers, _ := s.PeerIDsOf(ctx, []int64{devID})

	// Трафик ровный: запись каждые пять минут последние три часа, дальше — как на живом сервере:
	// Rollup раскладывает сырые записи по пятиминуткам, а те — по часам.
	now := time.Now()
	for m := 5; m <= 180; m += 5 {
		ts := now.Add(-time.Duration(m) * time.Minute).Unix()
		if _, err := s.DB().ExecContext(ctx, `INSERT OR REPLACE INTO traffic_raw (ts, peer_id, rx, tx) VALUES (?, ?, 1000, 100)`,
			ts-ts%15, peers[0]); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Rollup(ctx, 4*time.Hour); err != nil {
		t.Fatal(err)
	}
	// Панель работала всё это время.
	for m := 0; m <= 180; m += 5 {
		if err := s.InsertHostMetric(ctx, HostMetric{ServerID: srv, TS: now.Add(-time.Duration(m) * time.Minute), CPU: 1}); err != nil {
			t.Fatal(err)
		}
	}

	points, err := s.PeerSeries(ctx, peers, srv, now.Add(-windowDay), 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	// Смотрим только корзины последних двух часов: там трафик был в каждой.
	from := now.Add(-2 * time.Hour).Unix()
	var checked, empty int
	for _, p := range points {
		if p.TS < from || p.TS > now.Add(-30*time.Minute).Unix() {
			continue
		}
		checked++
		if p.Rx == 0 {
			empty++
		}
	}
	if checked < 3 {
		t.Fatalf("проверено корзин: %d — ряд короче ожидаемого", checked)
	}
	if empty > 0 {
		t.Fatalf("пустых корзин в ровном трафике: %d из %d — ряд взят из часовых агрегатов", empty, checked)
	}

	// Неделя и месяц по-прежнему считаются по часовым: сырых записей на такую глубину нет.
	week, err := s.PeerSeries(ctx, peers, srv, now.Add(-windowWeek), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var weekData uint64
	for _, p := range week {
		weekData += p.Rx
	}
	// 36 пятиминутных записей по 1000 — столько же должно оказаться в часовых агрегатах.
	if weekData != 36000 {
		t.Fatalf("недельный ряд: %d, ожидалось 36000 из часовых агрегатов", weekData)
	}
}
