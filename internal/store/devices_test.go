package store

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDeviceLimitsAndUniqueness(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	user, _, _ := s.CreateUser(ctx, User{Name: "Пётр", MaxDevices: 2})

	id, err := s.CreateDevice(ctx, Device{UserID: user, InterfaceID: iface.ID, Name: "Телефон", PublicKey: "P1", Address: "10.20.0.2", PrivateKey: "S1", PresharedKey: "K1"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := s.DeviceByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if d.Preset != PresetPhone || d.Status != "active" || d.CreatedBy != "admin" || d.UserName != "Пётр" || d.InterfaceName != "awg-old" {
		t.Fatalf("устройство по умолчанию: %+v", d)
	}
	if d.PrivateKey != "S1" || d.PresharedKey != "K1" {
		t.Fatal("секреты не сохранились")
	}

	if _, err := s.CreateDevice(ctx, Device{UserID: user, InterfaceID: iface.ID, Name: "телефон", PublicKey: "P2", Address: "10.20.0.3"}); err == nil {
		t.Fatal("имя устройства обязано быть уникальным у пользователя")
	}
	if _, err := s.CreateDevice(ctx, Device{UserID: user, InterfaceID: iface.ID, Name: "Ноутбук", PublicKey: "P1", Address: "10.20.0.4"}); err == nil {
		t.Fatal("публичный ключ обязан быть уникальным на интерфейсе")
	}
	if _, err := s.CreateDevice(ctx, Device{UserID: user, InterfaceID: iface.ID, Name: "Ноутбук", PublicKey: "P3", Address: "10.20.0.2"}); err == nil {
		t.Fatal("адрес обязан быть уникальным на интерфейсе")
	}
	if _, err := s.CreateDevice(ctx, Device{UserID: user, InterfaceID: iface.ID, Name: "Ноутбук", PublicKey: "P4", Address: "10.20.0.5"}); err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateDevice(ctx, Device{UserID: user, InterfaceID: iface.ID, Name: "Роутер", PublicKey: "P5", Address: "10.20.0.6"})
	if err == nil || !strings.Contains(err.Error(), "лимит") {
		t.Fatalf("лимит устройств: err = %v", err)
	}
	if _, err := s.CreateDevice(ctx, Device{UserID: 404, InterfaceID: iface.ID, Name: "Ничей", PublicKey: "P6", Address: "10.20.0.7"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("устройство несуществующему пользователю: %v", err)
	}
}

func TestDeviceNameValidation(t *testing.T) {
	ok := []string{"Телефон", "iPhone 15", "router-1", "my_pc.home", "Ж"}
	bad := []string{"", "   ", "плохое/имя", "sql'inj", strings.Repeat("я", 33)}
	for _, s := range ok {
		if err := ValidDeviceName(s); err != nil {
			t.Fatalf("%q должно приниматься: %v", s, err)
		}
	}
	for _, s := range bad {
		if err := ValidDeviceName(s); err == nil {
			t.Fatalf("%q должно отвергаться", s)
		}
	}
}

func TestDeviceStatusRotateAndTrash(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	user, _, _ := s.CreateUser(ctx, User{Name: "Ольга"})
	id, err := s.CreateDevice(ctx, Device{UserID: user, InterfaceID: iface.ID, Name: "Телефон", PublicKey: "OLD", Address: "10.20.0.2", PrivateKey: "OLDPRIV"})
	if err != nil {
		t.Fatal(err)
	}
	// Пир наблюдается на интерфейсе и связывается с устройством по ключу.
	now := time.Now()
	if _, err := s.ApplySample(ctx, iface.ID, now, []PeerSample{{PublicKey: "OLD", AllowedIPs: "10.20.0.2/32", LastHandshake: now.Add(-time.Minute)}}, OnlineWindow); err != nil {
		t.Fatal(err)
	}
	d, _ := s.DeviceByID(ctx, id)
	if !d.OnInterface || !d.Online() || d.PeerID == 0 {
		t.Fatalf("связь с пиром: %+v", d)
	}

	if err := s.SetDeviceStatus(ctx, id, "disabled"); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.DeviceByID(ctx, id); d.Active() {
		t.Fatal("выключенное устройство считается активным")
	}
	if err := s.SetDeviceStatus(ctx, id, "чужой"); err == nil {
		t.Fatal("принят недопустимый статус")
	}

	if err := s.RotateKeys(ctx, id, "NEWPRIV", "NEW", "NEWPSK"); err != nil {
		t.Fatal(err)
	}
	d, _ = s.DeviceByID(ctx, id)
	if d.PublicKey != "NEW" || d.PrivateKey != "NEWPRIV" || d.PresharedKey != "NEWPSK" {
		t.Fatalf("после перевыпуска: %+v", d)
	}
	if d.Address != "10.20.0.2" {
		t.Fatal("перевыпуск ключей сменил адрес")
	}
	if d.PeerID != 0 {
		t.Fatal("старый пир остался привязан к устройству")
	}

	if err := s.DeleteDevice(ctx, id); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.DevicesByUser(ctx, user); len(list) != 0 {
		t.Fatalf("удалённое устройство в списке: %+v", list)
	}
	trash, _ := s.DeletedDevices(ctx)
	if len(trash) != 1 || trash[0].ID != id {
		t.Fatalf("корзина устройств: %+v", trash)
	}
	if err := s.RestoreDevice(ctx, id); err != nil {
		t.Fatal(err)
	}
	if d, _ := s.DeviceByID(ctx, id); d.Status != "disabled" || !d.DeletedAt.IsZero() {
		t.Fatalf("после восстановления: %+v", d)
	}
}

func TestDevicesByInterfaceOnlyActive(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	a, _, _ := s.CreateUser(ctx, User{Name: "Активный"})
	b, _, _ := s.CreateUser(ctx, User{Name: "Выключенный"})
	if _, err := s.CreateDevice(ctx, Device{UserID: a, InterfaceID: iface.ID, Name: "A1", PublicKey: "A1", Address: "10.20.0.2"}); err != nil {
		t.Fatal(err)
	}
	idA2, _ := s.CreateDevice(ctx, Device{UserID: a, InterfaceID: iface.ID, Name: "A2", PublicKey: "A2", Address: "10.20.0.3"})
	if _, err := s.CreateDevice(ctx, Device{UserID: b, InterfaceID: iface.ID, Name: "B1", PublicKey: "B1", Address: "10.20.0.4"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetDeviceStatus(ctx, idA2, "disabled"); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserStatus(ctx, b, "disabled"); err != nil {
		t.Fatal(err)
	}
	all, err := s.DevicesByInterface(ctx, iface.ID, false)
	if err != nil || len(all) != 3 {
		t.Fatalf("все устройства = %d, err = %v", len(all), err)
	}
	// Желаемое состояние интерфейса: выключенные устройства и устройства выключенных пользователей в него не входят.
	active, err := s.DevicesByInterface(ctx, iface.ID, true)
	if err != nil || len(active) != 1 || active[0].Name != "A1" {
		t.Fatalf("активные устройства = %+v, err = %v", active, err)
	}
}

func TestNextAddress(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	user, _, _ := s.CreateUser(ctx, User{Name: "Адреса", MaxDevices: 10})

	// Первый свободный после адреса сервера 10.20.0.1.
	addr, err := s.NextAddress(ctx, iface)
	if err != nil || addr != "10.20.0.2" {
		t.Fatalf("первый адрес = %q, err = %v", addr, err)
	}
	if _, err := s.CreateDevice(ctx, Device{UserID: user, InterfaceID: iface.ID, Name: "d2", PublicKey: "k2", Address: addr}); err != nil {
		t.Fatal(err)
	}
	// Чужой пир (ещё не импортирован) занимает 10.20.0.3 — его адрес не выдаём.
	now := time.Now()
	if _, err := s.ApplySample(ctx, iface.ID, now, []PeerSample{{PublicKey: "чужой", AllowedIPs: "10.20.0.3/32"}}, OnlineWindow); err != nil {
		t.Fatal(err)
	}
	addr, err = s.NextAddress(ctx, iface)
	if err != nil || addr != "10.20.0.4" {
		t.Fatalf("после чужого пира = %q, err = %v", addr, err)
	}
	id4, err := s.CreateDevice(ctx, Device{UserID: user, InterfaceID: iface.ID, Name: "d4", PublicKey: "k4", Address: addr})
	if err != nil {
		t.Fatal(err)
	}
	// Мягко удалённое устройство держит адрес до окончательной очистки.
	if err := s.DeleteDevice(ctx, id4); err != nil {
		t.Fatal(err)
	}
	if addr, err := s.NextAddress(ctx, iface); err != nil || addr != "10.20.0.5" {
		t.Fatalf("удалённое устройство отдало адрес раньше очистки: %q, err = %v", addr, err)
	}
	if _, _, err := s.PurgeDeleted(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if addr, err := s.NextAddress(ctx, iface); err != nil || addr != "10.20.0.4" {
		t.Fatalf("после очистки адрес не вернулся в пул: %q, err = %v", addr, err)
	}
}

func TestNextAddressExhaustionAndErrors(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	srv, _ := s.UpsertLocalServer(ctx, "t", "t")
	// /30: сеть .0, широковещательный .3 — свободны только .1 (сервер) и .2.
	id, err := s.UpsertInterface(ctx, srv, "awg-t", InterfaceFacts{Subnet: "10.9.9.0/30", ServerAddress: "10.9.9.1/30"})
	if err != nil {
		t.Fatal(err)
	}
	list, _ := s.Interfaces(ctx, srv)
	var iface Interface
	for _, i := range list {
		if i.ID == id {
			iface = i
		}
	}
	user, _, _ := s.CreateUser(ctx, User{Name: "Тесный"})
	addr, err := s.NextAddress(ctx, iface)
	if err != nil || addr != "10.9.9.2" {
		t.Fatalf("адрес в /30 = %q, err = %v", addr, err)
	}
	if _, err := s.CreateDevice(ctx, Device{UserID: user, InterfaceID: iface.ID, Name: "один", PublicKey: "k", Address: addr}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.NextAddress(ctx, iface); err == nil {
		t.Fatal("в исчерпанной подсети выдан адрес")
	}
	if _, err := s.NextAddress(ctx, Interface{Subnet: "не подсеть"}); err == nil {
		t.Fatal("принята некорректная подсеть")
	}
}
