package hub

import (
	"context"
	"strings"
	"testing"

	"github.com/poznik/awgdash-pub/internal/store"
)

// Объединение сводит людей в одного: устройства переезжают, опустевший уходит в корзину (FR-2.7).
func TestMergeUsersMovesDevicesAndDeletesEmptied(t *testing.T) {
	ctx := context.Background()
	h, f, iface := testHub(t)
	iface = own(t, h, iface)
	nik, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Nik", MaxDevices: 5})
	poz, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Alex Doe", MaxDevices: 2})

	a, err := h.CreateDevice(ctx, NewDevice{UserID: nik, InterfaceID: iface.ID, Name: "n1", Preset: store.PresetPhone})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.CreateDevice(ctx, NewDevice{UserID: poz, InterfaceID: iface.ID, Name: "n1", Preset: store.PresetPhone}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.CreateDevice(ctx, NewDevice{UserID: poz, InterfaceID: iface.ID, Name: "ноут", Preset: store.PresetPhone}); err != nil {
		t.Fatal(err)
	}
	before := len(f.SetCalls())

	res, err := h.MergeUsers(ctx, MergeRequest{FromUserID: nik, ToUserID: poz, RaiseLimit: true, DeleteEmptied: true, Actor: store.ActorAdmin})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Moved) != 1 || res.Moved[0].Name != "n1 Nik" || !res.Deleted || res.NewLimit != 3 {
		t.Fatalf("итог объединения: %+v", res)
	}
	dev, err := h.Store.DeviceByID(ctx, a.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dev.UserID != poz || dev.Name != "n1 Nik" {
		t.Fatalf("устройство не переехало: %+v", dev)
	}
	// Пир остался тем же ключом: клиент переезда не замечает.
	if _, ok := f.Peers[a.PublicKey]; !ok {
		t.Fatalf("пир снят при переносе: %+v", f.Peers)
	}
	if len(f.SetCalls()) == before {
		t.Fatal("панель обязана переприменить пир после смены владельца")
	}
	gone, err := h.Store.UserByID(ctx, nik)
	if err != nil || gone.DeletedAt.IsZero() {
		t.Fatalf("опустевший пользователь должен уйти в корзину: %+v, err = %v", gone, err)
	}
	entries, err := h.Store.Audit(ctx, store.AuditFilter{Action: "user.merge"})
	if err != nil || len(entries) != 1 {
		t.Fatalf("аудит объединения: %+v, err = %v", entries, err)
	}
	moves, err := h.Store.Audit(ctx, store.AuditFilter{Action: "device.move"})
	if err != nil || len(moves) != 1 {
		t.Fatalf("аудит переноса: %+v, err = %v", moves, err)
	}
}

// Переезд к отключённому человеку снимает пир, возврат к активному — возвращает (FR-3.9).
func TestMoveDeviceAppliesNewOwnerStatus(t *testing.T) {
	ctx := context.Background()
	h, f, iface := testHub(t)
	iface = own(t, h, iface)
	active, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Анна", MaxDevices: 5})
	off, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Пётр", MaxDevices: 5})
	// CreateUser всегда заводит активного, поэтому статус ставится отдельно.
	if err := h.Store.SetUserStatus(ctx, off, "disabled"); err != nil {
		t.Fatal(err)
	}

	dev, err := h.CreateDevice(ctx, NewDevice{UserID: active, InterfaceID: iface.ID, Name: "Телефон", Preset: store.PresetPhone})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Peers[dev.PublicKey]; !ok {
		t.Fatal("пир не поставлен")
	}
	if _, err := h.MoveDevices(ctx, MoveRequest{DeviceIDs: []int64{dev.ID}, ToUserID: off, Actor: store.ActorAdmin}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Peers[dev.PublicKey]; ok {
		t.Fatal("у отключённого владельца пир обязан сняться")
	}
	if _, err := h.MoveDevices(ctx, MoveRequest{DeviceIDs: []int64{dev.ID}, ToUserID: active, Actor: store.ActorAdmin}); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Peers[dev.PublicKey]; !ok {
		t.Fatal("у активного владельца пир обязан вернуться")
	}
}

// Объединение с самим собой и перенос к несуществующему человеку отклоняются.
func TestMergeUsersRejectsNonsense(t *testing.T) {
	ctx := context.Background()
	h, _, iface := testHub(t)
	nik, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Nik", MaxDevices: 5})
	empty, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Пустой", MaxDevices: 5})
	if _, err := h.CreateDevice(ctx, NewDevice{UserID: nik, InterfaceID: iface.ID, Name: "n1"}); err != nil {
		t.Fatal(err)
	}

	if _, err := h.MergeUsers(ctx, MergeRequest{FromUserID: nik, ToUserID: nik}); err == nil {
		t.Fatal("объединение с самим собой должно отклоняться")
	}
	if _, err := h.MergeUsers(ctx, MergeRequest{FromUserID: empty, ToUserID: nik}); err == nil || !strings.Contains(err.Error(), "нет устройств") {
		t.Fatalf("пустого объединять нечем: %v", err)
	}
	if _, err := h.MoveDevices(ctx, MoveRequest{DeviceIDs: []int64{1}, ToUserID: 999}); err == nil {
		t.Fatal("перенос к несуществующему человеку должен отклоняться")
	}
}

// После записи пира панель обязана знать, что он на интерфейсе, не дожидаясь очередного обхода:
// свежесозданное устройство показывалось красным «нет на интерфейсе», хотя уже работало.
func TestNewDeviceIsSeenOnInterfaceAtOnce(t *testing.T) {
	ctx := context.Background()
	h, f, iface := testHub(t)
	iface = own(t, h, iface)
	// Обход наполняет карту интерфейсов — в бою это делает старт хаба.
	if err := h.discover(ctx); err != nil {
		t.Fatal(err)
	}
	user, _, _ := h.Store.CreateUser(ctx, store.User{Name: "Анна", MaxDevices: 5})

	dev, err := h.CreateDevice(ctx, NewDevice{UserID: user, InterfaceID: iface.ID, Name: "Телефон", Preset: store.PresetPhone})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Peers[dev.PublicKey]; !ok {
		t.Fatal("пир не поставлен")
	}
	fresh, err := h.Store.DeviceByID(ctx, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !fresh.OnInterface {
		t.Fatal("панель не видит только что поставленный пир — статус «нет на интерфейсе» врёт")
	}
}
