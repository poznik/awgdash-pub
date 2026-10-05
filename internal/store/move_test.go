package store

import (
	"context"
	"strings"
	"testing"
)

// devFor — устройство пользователя с предсказуемыми ключом и адресом.
func devFor(t *testing.T, s *Store, user, iface int64, name, suffix string) int64 {
	t.Helper()
	id, err := s.CreateDevice(context.Background(), Device{UserID: user, InterfaceID: iface, Name: name,
		PublicKey: "P" + suffix, PrivateKey: "S" + suffix, PresharedKey: "K" + suffix, Address: "10.20.0." + suffix})
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// Перенос не трогает ключи, адрес и интерфейс: для клиента ничего не меняется (FR-3.9).
func TestMoveDeviceKeepsKeysAndAddress(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	from, _, _ := s.CreateUser(ctx, User{Name: "Nik", MaxDevices: 5})
	to, _, _ := s.CreateUser(ctx, User{Name: "Alex Doe", MaxDevices: 5})
	id := devFor(t, s, from, iface.ID, "n1", "2")

	before, err := s.DeviceByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.MoveDevices(ctx, []int64{id}, to, MoveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Moved) != 1 || res.Moved[0].Renamed() || res.NewLimit != 0 || len(res.Foreign) != 0 {
		t.Fatalf("итог переноса: %+v", res)
	}
	after, err := s.DeviceByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if after.UserID != to || after.UserName != "Alex Doe" {
		t.Fatalf("владелец не сменился: %+v", after)
	}
	if after.PublicKey != before.PublicKey || after.PrivateKey != before.PrivateKey ||
		after.PresharedKey != before.PresharedKey || after.Address != before.Address || after.InterfaceID != before.InterfaceID {
		t.Fatalf("перенос тронул то, что видит клиент: было %+v, стало %+v", before, after)
	}
}

// Занятое имя получает суффикс с именем прежнего владельца, следующее — с номером (FR-3.9).
func TestMoveDeviceRenamesOnConflict(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	nik, _, _ := s.CreateUser(ctx, User{Name: "Nik", MaxDevices: 5})
	me, _, _ := s.CreateUser(ctx, User{Name: "_ME", MaxDevices: 5})
	poz, _, _ := s.CreateUser(ctx, User{Name: "Alex Doe", MaxDevices: 9})
	devFor(t, s, poz, iface.ID, "n1", "2")
	a := devFor(t, s, nik, iface.ID, "n1", "3")
	b := devFor(t, s, me, iface.ID, "n1", "4")

	res, err := s.MoveDevices(ctx, []int64{a}, poz, MoveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Moved[0].Name != "n1 Nik" || res.Renamed() != 1 {
		t.Fatalf("ожидали «n1 Nik», получили %+v", res.Moved)
	}
	// Второй «n1» приезжает от другого человека: имя с его именем свободно.
	res, err = s.MoveDevices(ctx, []int64{b}, poz, MoveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Moved[0].Name != "n1 _ME" {
		t.Fatalf("ожидали «n1 _ME», получили %q", res.Moved[0].Name)
	}
	// Третий «n1» от того же Nik — суффикс уже занят, добавляется номер.
	c := devFor(t, s, nik, iface.ID, "n1", "5")
	res, err = s.MoveDevices(ctx, []int64{c}, poz, MoveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Moved[0].Name != "n1 Nik 2" {
		t.Fatalf("ожидали «n1 Nik 2», получили %q", res.Moved[0].Name)
	}
}

// Лимит нового владельца соблюдается; при отказе не переезжает ни одно устройство (FR-2.7).
func TestMoveDevicesLimitIsAtomic(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	from, _, _ := s.CreateUser(ctx, User{Name: "Nik", MaxDevices: 5})
	to, _, _ := s.CreateUser(ctx, User{Name: "Alex Doe", MaxDevices: 2})
	devFor(t, s, to, iface.ID, "телефон", "2")
	a := devFor(t, s, from, iface.ID, "n1", "3")
	b := devFor(t, s, from, iface.ID, "n2", "4")

	_, err := s.MoveDevices(ctx, []int64{a, b}, to, MoveOptions{})
	if err == nil || !strings.Contains(err.Error(), "лимит") {
		t.Fatalf("перенос сверх лимита должен отказывать, получили %v", err)
	}
	left, err := s.DevicesByUser(ctx, from)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 2 {
		t.Fatalf("после отказа устройства должны остаться на месте, осталось %d", len(left))
	}

	res, err := s.MoveDevices(ctx, []int64{a, b}, to, MoveOptions{RaiseLimit: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.NewLimit != 3 {
		t.Fatalf("лимит должен подняться до 3, получили %d", res.NewLimit)
	}
	u, err := s.UserByID(ctx, to)
	if err != nil {
		t.Fatal(err)
	}
	if u.MaxDevices != 3 {
		t.Fatalf("лимит в БД: %d", u.MaxDevices)
	}
}

// Устройство из корзины не переносится, а уже своё — пропускается (FR-3.9).
func TestMoveDevicesSkipsTrashAndOwn(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	from, _, _ := s.CreateUser(ctx, User{Name: "Nik", MaxDevices: 5})
	to, _, _ := s.CreateUser(ctx, User{Name: "Alex Doe", MaxDevices: 5})
	trashed := devFor(t, s, from, iface.ID, "старое", "2")
	own := devFor(t, s, to, iface.ID, "своё", "3")
	live := devFor(t, s, from, iface.ID, "живое", "4")
	if err := s.DeleteDevice(ctx, trashed); err != nil {
		t.Fatal(err)
	}

	if _, err := s.MoveDevices(ctx, []int64{trashed}, to, MoveOptions{}); err == nil {
		t.Fatal("устройство из корзины переносить нельзя")
	}
	res, err := s.MoveDevices(ctx, []int64{own, live}, to, MoveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped != 1 || len(res.Moved) != 1 || res.Moved[0].ID != live {
		t.Fatalf("своё устройство должно пропускаться: %+v", res)
	}
	n, err := s.CountTrashedDevices(ctx, from)
	if err != nil || n != 1 {
		t.Fatalf("в корзине у прежнего владельца ожидалось 1, получили %d (%v)", n, err)
	}
}

// Сервер вне списка разрешённых новому владельцу не мешает переносу, но попадает в отчёт (FR-3.9).
func TestMoveDeviceReportsForeignServer(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	from, _, _ := s.CreateUser(ctx, User{Name: "Nik", MaxDevices: 5})
	to, _, _ := s.CreateUser(ctx, User{Name: "Alex Doe", MaxDevices: 5, AllowedInterfaces: []int64{iface.ID + 100}})
	id := devFor(t, s, from, iface.ID, "n1", "2")

	res, err := s.MoveDevices(ctx, []int64{id}, to, MoveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Foreign) != 1 || res.Foreign[0] != "n1" {
		t.Fatalf("устройство на неразрешённом сервере должно попасть в отчёт: %+v", res)
	}
}

func TestFitDeviceName(t *testing.T) {
	long := strings.Repeat("и", 30)
	got := fitDeviceName(long, " Александр")
	if n := len([]rune(got)); n > 32 {
		t.Fatalf("имя длиннее 32 рун: %d (%q)", n, got)
	}
	if !strings.HasSuffix(got, " Александр") {
		t.Fatalf("суффикс должен уцелеть: %q", got)
	}
	if got := deviceNamePart("Пётр (шеф) #1"); got != "Пётр шеф 1" {
		t.Fatalf("недопустимые символы должны уходить: %q", got)
	}
}
