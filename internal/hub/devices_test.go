package hub

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/poznik/awgdash-pub/internal/awgtest"
	"github.com/poznik/awgdash-pub/internal/config"
	"github.com/poznik/awgdash-pub/internal/node"
	"github.com/poznik/awgdash-pub/internal/store"
)

// testHub поднимает хаб на временной БД и модели awg: интерфейс awg-t0 с двумя чужими пирами.
func testHub(t *testing.T) (*Hub, *awgtest.Fake, store.Interface) {
	t.Helper()
	ctx := context.Background()
	dir := t.TempDir()
	confDir := filepath.Join(dir, "etc")
	if _, err := awgtest.WriteConf(confDir, "awg-t0"); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })

	f := awgtest.New()
	n := node.New(confDir, "awg", f, []string{"wg-dashboard.service"})
	n.BackupDir = filepath.Join(dir, "conf-backup")
	cfg := &config.Config{ServerSlug: "de", ServerTitle: "Германия"}
	h := New(cfg, st, n, slog.New(slog.NewTextHandler(io.Discard, nil)))

	srv, err := st.UpsertLocalServer(ctx, "de", "Германия")
	if err != nil {
		t.Fatal(err)
	}
	h.ServerID = srv
	h.registerLocal()
	if _, err := st.UpsertInterface(ctx, srv, "awg-t0", store.InterfaceFacts{
		Subnet: "10.20.0.0/16", ServerAddress: "10.20.0.1/16", ListenPort: 443, MTU: 1280, IsAWG: true,
		ServerPublicKey: awgtest.ServerPublicKey,
	}); err != nil {
		t.Fatal(err)
	}
	list, err := st.Interfaces(ctx, srv)
	if err != nil || len(list) != 1 {
		t.Fatalf("interfaces = %+v, err = %v", list, err)
	}
	return h, f, list[0]
}

// own переводит интерфейс в режим own в обход предпроверок (в тестах они проверяются отдельно).
func own(t *testing.T, h *Hub, iface store.Interface) store.Interface {
	t.Helper()
	if err := h.Store.SetInterfaceMode(context.Background(), iface.ID, ModeOwn); err != nil {
		t.Fatal(err)
	}
	fresh, err := h.Interface(context.Background(), iface.ID)
	if err != nil {
		t.Fatal(err)
	}
	return fresh
}

func TestCreateDeviceObserveDoesNotWrite(t *testing.T) {
	ctx := context.Background()
	h, f, iface := testHub(t)
	user, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Анна"})

	dev, err := h.CreateDevice(ctx, NewDevice{UserID: user, InterfaceID: iface.ID, Name: "Телефон"})
	if err != nil {
		t.Fatal(err)
	}
	// Пиры интерфейса попадают в БД только после обхода, поэтому в чистой БД занят лишь адрес сервера.
	if dev.Address != "10.20.0.2" {
		t.Fatalf("адрес: %s", dev.Address)
	}
	if dev.PrivateKey == "" || dev.PublicKey == "" {
		t.Fatal("ключи не сгенерированы")
	}
	if len(f.SetCalls()) != 0 {
		t.Fatalf("в режиме observe панель писала в интерфейс: %v", f.SetCalls())
	}
	entries, err := h.Store.Audit(ctx, store.AuditFilter{Action: "device.create"})
	if err != nil || len(entries) != 1 {
		t.Fatalf("аудит: %+v, err = %v", entries, err)
	}
	if strings.Contains(entries[0].Details["name"].(string), "ключ") {
		t.Fatal("в аудите оказались лишние поля")
	}
}

func TestCreateDeviceOwnWritesPeer(t *testing.T) {
	ctx := context.Background()
	h, f, iface := testHub(t)
	iface = own(t, h, iface)
	user, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Анна"})

	dev, err := h.CreateDevice(ctx, NewDevice{UserID: user, InterfaceID: iface.ID, Name: "Телефон", Preset: store.PresetPhone})
	if err != nil {
		t.Fatal(err)
	}
	p, ok := f.Peers[dev.PublicKey]
	if !ok {
		t.Fatalf("пир не поставлен: %+v", f.Peers)
	}
	if p.Allowed != dev.Address+"/32" {
		t.Fatalf("allowed-ips пира: %q, адрес устройства %s", p.Allowed, dev.Address)
	}
	if !p.HasPSK {
		t.Fatal("PSK не поставлен, хотя на интерфейсе он включён")
	}
	// Секреты не должны утекать в аудит и события.
	entries, _ := h.Store.Audit(ctx, store.AuditFilter{})
	for _, e := range entries {
		for k, v := range e.Details {
			if s, ok := v.(string); ok && (s == dev.PrivateKey || s == dev.PresharedKey) {
				t.Fatalf("секрет в аудите: %s = %q", k, s)
			}
		}
	}
	events, _ := h.Store.Events(ctx, 10)
	for _, e := range events {
		if strings.Contains(e.Message, dev.PrivateKey) || strings.Contains(e.Message, dev.PresharedKey) {
			t.Fatalf("секрет в событии: %s", e.Message)
		}
	}
}

func TestDeviceStatusAndDeleteMovePeer(t *testing.T) {
	ctx := context.Background()
	h, f, iface := testHub(t)
	iface = own(t, h, iface)
	user, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Анна"})
	dev, err := h.CreateDevice(ctx, NewDevice{UserID: user, InterfaceID: iface.ID, Name: "Телефон"})
	if err != nil {
		t.Fatal(err)
	}

	if err := h.SetDeviceStatus(ctx, dev.ID, "disabled", store.ActorAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Peers[dev.PublicKey]; ok {
		t.Fatal("пир выключенного устройства остался на интерфейсе")
	}
	if err := h.SetDeviceStatus(ctx, dev.ID, "active", store.ActorAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Peers[dev.PublicKey]; !ok {
		t.Fatal("пир не вернулся теми же ключами")
	}

	if err := h.DeleteDevice(ctx, dev.ID, store.ActorAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Peers[dev.PublicKey]; ok {
		t.Fatal("пир удалённого устройства остался")
	}
	after, err := h.Store.DeviceByID(ctx, dev.ID)
	if err != nil || after.DeletedAt.IsZero() {
		t.Fatalf("устройство не в корзине: %+v, err = %v", after, err)
	}
	// Адрес держится за корзиной до окончательной очистки.
	next, err := h.Store.NextAddress(ctx, iface)
	if err != nil {
		t.Fatal(err)
	}
	if next == dev.Address {
		t.Fatal("адрес удалённого устройства выдан заново")
	}
}

func TestUserDisableRemovesAllPeers(t *testing.T) {
	ctx := context.Background()
	h, f, iface := testHub(t)
	iface = own(t, h, iface)
	user, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Ирина"})
	d1, err := h.CreateDevice(ctx, NewDevice{UserID: user, InterfaceID: iface.ID, Name: "Телефон"})
	if err != nil {
		t.Fatal(err)
	}
	d2, err := h.CreateDevice(ctx, NewDevice{UserID: user, InterfaceID: iface.ID, Name: "Ноутбук"})
	if err != nil {
		t.Fatal(err)
	}

	if err := h.SetUserStatus(ctx, user, "disabled", store.ActorAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Peers[d1.PublicKey]; ok {
		t.Fatal("пир первого устройства остался")
	}
	if _, ok := f.Peers[d2.PublicKey]; ok {
		t.Fatal("пир второго устройства остался")
	}
	if err := h.SetUserStatus(ctx, user, "active", store.ActorAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Peers[d1.PublicKey]; !ok {
		t.Fatal("пир не вернулся при включении пользователя")
	}
	// Ключи и адреса не менялись.
	fresh, _ := h.Store.DeviceByID(ctx, d1.ID)
	if fresh.PublicKey != d1.PublicKey || fresh.Address != d1.Address {
		t.Fatalf("устройство изменилось: %+v", fresh)
	}
}

func TestRotateKeysReplacesPeerKeepingAddress(t *testing.T) {
	ctx := context.Background()
	h, f, iface := testHub(t)
	iface = own(t, h, iface)
	user, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Анна"})
	dev, err := h.CreateDevice(ctx, NewDevice{UserID: user, InterfaceID: iface.ID, Name: "Телефон"})
	if err != nil {
		t.Fatal(err)
	}
	oldPub := dev.PublicKey

	fresh, err := h.RotateKeys(ctx, dev.ID, store.ActorAdmin, "")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.PublicKey == oldPub {
		t.Fatal("ключ не сменился")
	}
	if fresh.Address != dev.Address {
		t.Fatalf("адрес сменился: %s → %s", dev.Address, fresh.Address)
	}
	if _, ok := f.Peers[oldPub]; ok {
		t.Fatal("старый пир остался на интерфейсе")
	}
	if p, ok := f.Peers[fresh.PublicKey]; !ok || p.Allowed != fresh.Address+"/32" {
		t.Fatalf("новый пир: %+v", f.Peers)
	}
}

func TestDeviceConfigAndAudit(t *testing.T) {
	ctx := context.Background()
	h, _, iface := testHub(t)
	user, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Анна"})
	dev, err := h.CreateDevice(ctx, NewDevice{UserID: user, InterfaceID: iface.ID, Name: "Телефон"})
	if err != nil {
		t.Fatal(err)
	}
	// Интерфейсу нужен вариант endpoint: без него конфиг не собрать.
	if _, err := h.Store.DB().ExecContext(ctx, `UPDATE interfaces SET endpoints = ? WHERE id = ?`,
		`[{"label":"основной","host":"vpn.example.com","port":443,"primary":true}]`, iface.ID); err != nil {
		t.Fatal(err)
	}

	cfg, err := h.DeviceConfig(ctx, dev.ID, "", store.ActorAdmin, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cfg.Text, "Endpoint = vpn.example.com:443") || !strings.Contains(cfg.Text, "Address = "+dev.Address+"/32") {
		t.Fatalf("конфиг:\n%s", cfg.Text)
	}
	if !strings.HasPrefix(cfg.SVG, "<svg") {
		t.Fatal("QR не отрисован")
	}
	if cfg.FileName != "Анна-Телефон.conf" {
		t.Fatalf("имя файла: %s", cfg.FileName)
	}
	if cfg.TooLong {
		t.Fatalf("конфиг признан слишком длинным: %d символов", len(cfg.Text))
	}
	entries, _ := h.Store.Audit(ctx, store.AuditFilter{Action: "device.config_issued"})
	if len(entries) != 1 || entries[0].IP != "127.0.0.1" {
		t.Fatalf("аудит выдачи: %+v", entries)
	}
	for _, v := range entries[0].Details {
		if s, ok := v.(string); ok && strings.Contains(s, "PrivateKey") {
			t.Fatal("в аудит попал конфиг")
		}
	}
	after, _ := h.Store.DeviceByID(ctx, dev.ID)
	if after.IssueCount != 1 || after.IssuedAt.IsZero() {
		t.Fatalf("выдача не отмечена: %+v", after)
	}
}

func TestGuardBlocksCreateInOwn(t *testing.T) {
	ctx := context.Background()
	h, f, iface := testHub(t)
	iface = own(t, h, iface)
	f.Foreign = true // WGDashboard снова запустили
	user, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Анна"})

	_, err := h.CreateDevice(ctx, NewDevice{UserID: user, InterfaceID: iface.ID, Name: "Телефон"})
	if err == nil {
		t.Fatal("устройство создано вопреки охранной проверке")
	}
	devs, _ := h.Store.DevicesByUser(ctx, user)
	if len(devs) != 0 {
		t.Fatalf("устройство осталось в БД: %+v", devs)
	}
	events, _ := h.Store.Events(ctx, 10)
	found := false
	for _, e := range events {
		if e.Kind == "guard" {
			found = true
		}
	}
	if !found {
		t.Fatalf("событие guard не записано: %+v", events)
	}
}

func TestModeReadinessAndSwitch(t *testing.T) {
	ctx := context.Background()
	h, f, iface := testHub(t)

	// Пиры интерфейса попали в БД при обходе и никому не принадлежат.
	if _, err := h.Store.ApplySample(ctx, iface.ID, time.Now(), []store.PeerSample{
		{PublicKey: awgtest.KeyA, AllowedIPs: "10.20.0.2/32"},
		{PublicKey: awgtest.KeyB, AllowedIPs: "10.20.0.3/32"},
	}, store.OnlineWindow); err != nil {
		t.Fatal(err)
	}
	rd, err := h.ModeReadiness(ctx, iface.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if rd.Ready || len(rd.Unassigned) != 2 {
		t.Fatalf("готовность при нераспределённых пирах: %+v", rd)
	}
	if _, err := h.SwitchInterfaceMode(ctx, iface.ID, ModeOwn, store.ActorAdmin, ""); err == nil {
		t.Fatal("переход в own прошёл с нераспределёнными пирами")
	}

	// Импортируем пиры как устройства — связь ставится по публичному ключу.
	user, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Анна"})
	for i, key := range []string{awgtest.KeyA, awgtest.KeyB} {
		if _, err := h.Store.CreateDevice(ctx, store.Device{
			UserID: user, InterfaceID: iface.ID, Name: "устройство " + string(rune('A'+i)),
			PublicKey: key, Address: "10.20.0." + string(rune('2'+i)), CreatedBy: "import",
		}); err != nil {
			t.Fatal(err)
		}
	}
	rd, err = h.ModeReadiness(ctx, iface.ID, true)
	if err != nil {
		t.Fatal(err)
	}
	if !rd.Ready {
		t.Fatalf("после импорта интерфейс не готов: %+v", rd)
	}
	if rd, err = h.SwitchInterfaceMode(ctx, iface.ID, ModeOwn, store.ActorAdmin, ""); err != nil {
		t.Fatal(err)
	}
	if rd.Mode != ModeOwn {
		t.Fatalf("режим: %s", rd.Mode)
	}

	// Чужой менеджер снова активен — готовность падает, но возврат в observe возможен всегда.
	f.Foreign = true
	rd, _ = h.ModeReadiness(ctx, iface.ID, true)
	if rd.Ready {
		t.Fatal("готовность не учла чужой менеджер")
	}
	if _, err := h.SwitchInterfaceMode(ctx, iface.ID, "observe", store.ActorAdmin, ""); err != nil {
		t.Fatalf("откат в observe: %v", err)
	}
}

func TestReconcileInterfaceFromDB(t *testing.T) {
	ctx := context.Background()
	h, f, iface := testHub(t)
	iface = own(t, h, iface)
	user, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Анна"})
	dev, err := h.CreateDevice(ctx, NewDevice{UserID: user, InterfaceID: iface.ID, Name: "Телефон"})
	if err != nil {
		t.Fatal(err)
	}

	res, err := h.ReconcileInterface(ctx, iface.ID, store.ActorAdmin, "")
	if err != nil {
		t.Fatal(err)
	}
	// Чужие пиры из файла не значатся устройствами — reconcile их снимает.
	if len(res.Removed) != 2 {
		t.Fatalf("removed = %v", res.Removed)
	}
	if len(f.Peers) != 1 {
		t.Fatalf("на интерфейсе осталось: %+v", f.Peers)
	}
	if _, ok := f.Peers[dev.PublicKey]; !ok {
		t.Fatal("устройство панели снято")
	}
	// В режиме observe reconcile запрещён.
	if err := h.Store.SetInterfaceMode(ctx, iface.ID, "observe"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.ReconcileInterface(ctx, iface.ID, store.ActorAdmin, ""); err == nil {
		t.Fatal("reconcile прошёл в режиме observe")
	}
}

func TestHousekeeping(t *testing.T) {
	ctx := context.Background()
	h, f, iface := testHub(t)
	iface = own(t, h, iface)

	// Пользователь с истёкшим сроком: уборка закрывает доступ и снимает пиры.
	expired, _, err := h.Store.CreateUser(ctx, store.User{Name: "Срок вышел", ExpiresAt: time.Now().Add(-time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := h.CreateDevice(ctx, NewDevice{UserID: expired, InterfaceID: iface.ID, Name: "Телефон"})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Peers[dev.PublicKey]; !ok {
		t.Fatal("пир не поставлен до уборки")
	}

	// Просроченная сессия и старая корзина.
	adminID, err := h.Store.CreateAdmin(ctx, "admin", "$argon2id$хеш")
	if err != nil {
		t.Fatal(err)
	}
	ses, _ := h.Store.CreateSession(ctx, adminID, "10.0.0.1", "ua")
	if _, err := h.Store.DB().ExecContext(ctx, `UPDATE sessions SET expires_at = ? WHERE id = ?`, time.Now().Add(-time.Hour).Unix(), ses.ID); err != nil {
		t.Fatal(err)
	}
	trashed, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Давно удалён"})
	if err := h.Store.DeleteUser(ctx, trashed); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-40 * 24 * time.Hour).Unix()
	if _, err := h.Store.DB().ExecContext(ctx, `UPDATE users SET deleted_at = ? WHERE id = ?`, old, trashed); err != nil {
		t.Fatal(err)
	}

	if err := h.housekeeping(ctx); err != nil {
		t.Fatal(err)
	}
	u, _ := h.Store.UserByID(ctx, expired)
	if !u.Disabled() {
		t.Fatal("пользователь с истёкшим сроком не отключён")
	}
	if _, ok := f.Peers[dev.PublicKey]; ok {
		t.Fatal("пир истёкшего пользователя остался на интерфейсе")
	}
	var sessions int
	h.Store.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions`).Scan(&sessions)
	if sessions != 0 {
		t.Fatalf("просроченных сессий осталось: %d", sessions)
	}
	if _, err := h.Store.UserByID(ctx, trashed); err == nil {
		t.Fatal("старая корзина не очищена")
	}
	// Свежая корзина не трогается: у администратора есть 30 дней передумать.
	if u, _ := h.Store.UserByID(ctx, expired); u.ID == 0 {
		t.Fatal("уборка удалила действующего пользователя")
	}
}

// Адрес устройства превращается в префикс allowed-ips ровно один раз. У усыновлённых
// служебных пиров (межсерверные туннели ru) в адресе уже стоит префикс 0.0.0.0/0, и вторая
// маска давала «0.0.0.0/0/32»: такая строка уходила в конфиг интерфейса, а сверка на ней
// спотыкалась. Нашлось на живом парке при проверке валидации пиров.
func TestAddrPrefixAddsMaskOnce(t *testing.T) {
	cases := map[string]string{
		"10.20.0.7":    "10.20.0.7/32",
		"10.20.0.7/32": "10.20.0.7/32",
		"0.0.0.0/0":    "0.0.0.0/0",
		" 10.8.0.5 ":   "10.8.0.5/32",
		"":             "",
	}
	for in, want := range cases {
		if got := addrPrefix(in); got != want {
			t.Errorf("addrPrefix(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}

// Имя по умолчанию живёт на сервере: форма показывает его серым, а не вписывает в поле, поэтому
// пустое имя — это «назови сам» и панель подставляет то же самое, что человек видел.
func TestCreateDeviceWithoutNameTakesDefault(t *testing.T) {
	ctx := context.Background()
	h, _, iface := testHub(t)
	iface = own(t, h, iface)
	user, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Анна", MaxDevices: 5})

	first, err := h.CreateDevice(ctx, NewDevice{UserID: user, InterfaceID: iface.ID})
	if err != nil {
		t.Fatal(err)
	}
	if first.Name != "Устройство 1" {
		t.Fatalf("первое устройство названо %q", first.Name)
	}
	second, err := h.CreateDevice(ctx, NewDevice{UserID: user, InterfaceID: iface.ID, Name: "   "})
	if err != nil {
		t.Fatal(err)
	}
	if second.Name != "Устройство 2" {
		t.Fatalf("второе устройство названо %q", second.Name)
	}

	// Занятый номер пропускается: имя обязано быть уникальным у владельца, и отказ на пустом
	// поле выглядел бы как поломка формы. Здесь устройств станет три, счёт даёт «Устройство 4»,
	// а его уже занял названный вручную — значит следующее свободное «Устройство 5».
	if _, err := h.CreateDevice(ctx, NewDevice{UserID: user, InterfaceID: iface.ID, Name: "Устройство 4"}); err != nil {
		t.Fatal(err)
	}
	fourth, err := h.CreateDevice(ctx, NewDevice{UserID: user, InterfaceID: iface.ID})
	if err != nil {
		t.Fatal(err)
	}
	if fourth.Name != "Устройство 5" {
		t.Fatalf("после занятого номера устройство названо %q, ожидалось «Устройство 5»", fourth.Name)
	}
}
