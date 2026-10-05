package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

// testIface создаёт сервер и интерфейс с подсетью 10.20.0.0/16 и сервером на .1.
func testIface(t *testing.T, s *Store) Interface {
	t.Helper()
	ctx := context.Background()
	srv, err := s.UpsertLocalServer(ctx, "de", "Германия")
	if err != nil {
		t.Fatal(err)
	}
	id, err := s.UpsertInterface(ctx, srv, "awg-old", InterfaceFacts{Subnet: "10.20.0.0/16", ServerAddress: "10.20.0.1/16", ListenPort: 443, MTU: 1280, IsAWG: true})
	if err != nil {
		t.Fatal(err)
	}
	list, err := s.Interfaces(ctx, srv)
	if err != nil || len(list) != 1 || list[0].ID != id {
		t.Fatalf("interfaces = %+v, err = %v", list, err)
	}
	return list[0]
}

func TestUserCRUDAndLink(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)

	id, token, err := s.CreateUser(ctx, User{Name: "Анна", Note: "себе", SelfService: true, DefaultInterfaceID: iface.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < 40 {
		t.Fatalf("токен слишком короткий: %q", token)
	}
	u, err := s.UserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if u.Name != "Анна" || !u.SelfService || u.MaxDevices != 5 || u.Token != token || u.Status != "active" {
		t.Fatalf("user = %+v", u)
	}
	if _, _, err := s.CreateUser(ctx, User{Name: "Анна"}); err == nil {
		t.Fatal("имя пользователя обязано быть уникальным")
	}

	byToken, err := s.UserByToken(ctx, token)
	if err != nil || byToken.ID != id {
		t.Fatalf("UserByToken = %+v, err = %v", byToken, err)
	}
	if _, err := s.UserByToken(ctx, "чужой"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("чужой токен: err = %v", err)
	}

	// Перевыпуск ссылки гасит старую (FR-2.4).
	fresh, err := s.IssueLink(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.UserByToken(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Fatal("старая ссылка осталась рабочей")
	}
	if _, err := s.UserByToken(ctx, fresh); err != nil {
		t.Fatal(err)
	}

	u.Name, u.MaxDevices, u.Note = "Анна П.", 3, "правка"
	if err := s.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	u, _ = s.UserByID(ctx, id)
	if u.Name != "Анна П." || u.MaxDevices != 3 || u.Note != "правка" {
		t.Fatalf("после UpdateUser: %+v", u)
	}
	if err := s.UpdateUser(ctx, User{ID: 999, Name: "нет"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("UpdateUser несуществующего: %v", err)
	}
}

func TestUserExpiryAndTrash(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	id, _, err := s.CreateUser(ctx, User{Name: "Гость", ExpiresAt: time.Now().Add(-time.Hour), DefaultInterfaceID: iface.ID})
	if err != nil {
		t.Fatal(err)
	}
	dev := Device{UserID: id, InterfaceID: iface.ID, Name: "телефон", PublicKey: "PUB1", Address: "10.20.0.7"}
	if _, err := s.CreateDevice(ctx, dev); err != nil {
		t.Fatal(err)
	}
	ids, err := s.ExpireUsers(ctx)
	if err != nil || len(ids) != 1 || ids[0] != id {
		t.Fatalf("ExpireUsers = %v, err = %v", ids, err)
	}
	u, _ := s.UserByID(ctx, id)
	if !u.Disabled() || !u.Expired() {
		t.Fatalf("после срока: %+v", u)
	}
	// Повторный прогон никого не трогает.
	if ids, _ := s.ExpireUsers(ctx); len(ids) != 0 {
		t.Fatalf("повторный ExpireUsers = %v", ids)
	}

	if err := s.DeleteUser(ctx, id); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.CreateUser(ctx, User{Name: "Гость"}); err != nil {
		t.Fatalf("имя удалённого должно освобождаться: %v", err)
	}
	list, total, err := s.Users(ctx, UserFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(list) != 1 || list[0].Name != "Гость" || list[0].ID == id {
		t.Fatalf("активные = %+v (total %d)", list, total)
	}
	trash, _, _ := s.Users(ctx, UserFilter{Deleted: true})
	if len(trash) != 1 || trash[0].ID != id {
		t.Fatalf("корзина = %+v", trash)
	}
	devs, _ := s.DevicesByUser(ctx, id)
	if len(devs) != 0 {
		t.Fatalf("устройства удалённого пользователя видны: %+v", devs)
	}

	// Очистка не трогает свежее.
	if users, devices, err := s.PurgeDeleted(ctx, PurgeAfter); err != nil || users != 0 || devices != 0 {
		t.Fatalf("PurgeDeleted раньше срока: %d/%d, err = %v", users, devices, err)
	}
	if users, devices, err := s.PurgeDeleted(ctx, 0); err != nil || users != 1 || devices != 1 {
		t.Fatalf("PurgeDeleted = %d/%d, err = %v", users, devices, err)
	}
	if _, err := s.UserByID(ctx, id); !errors.Is(err, ErrNotFound) {
		t.Fatalf("после очистки: %v", err)
	}
}

func TestUserRestoreKeepsDevices(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	id, _, _ := s.CreateUser(ctx, User{Name: "Аня"})
	devID, err := s.CreateDevice(ctx, Device{UserID: id, InterfaceID: iface.ID, Name: "ноутбук", PublicKey: "PUBA", Address: "10.20.0.9"})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteUser(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := s.RestoreUser(ctx, id); err != nil {
		t.Fatal(err)
	}
	u, err := s.UserByID(ctx, id)
	if err != nil || !u.DeletedAt.IsZero() {
		t.Fatalf("восстановленный: %+v, err = %v", u, err)
	}
	if u.Token == "" {
		t.Fatal("после восстановления нет действующей ссылки")
	}
	d, err := s.DeviceByID(ctx, devID)
	if err != nil {
		t.Fatal(err)
	}
	if d.Status != "disabled" || !d.DeletedAt.IsZero() || d.PublicKey != "PUBA" || d.Address != "10.20.0.9" {
		t.Fatalf("устройство после восстановления: %+v", d)
	}
}

func TestUserFilters(t *testing.T) {
	s := openTest(t)
	ctx := context.Background()
	iface := testIface(t, s)
	a, _, _ := s.CreateUser(ctx, User{Name: "Анна", Note: "семья", SelfService: true})
	b, _, _ := s.CreateUser(ctx, User{Name: "Борис", Note: "работа"})
	if _, _, err := s.CreateUser(ctx, User{Name: "Виктор"}); err != nil {
		t.Fatal(err)
	}
	if err := s.SetUserStatus(ctx, b, "disabled"); err != nil {
		t.Fatal(err)
	}
	// Онлайн: у Анны устройство с недавним хендшейком.
	devID, _ := s.CreateDevice(ctx, Device{UserID: a, InterfaceID: iface.ID, Name: "телефон", PublicKey: "PA", Address: "10.20.0.2"})
	now := time.Now()
	// Первый сэмпл задаёт базу счётчиков, второй даёт дельту — она и попадает в трафик за сутки.
	base := PeerSample{PublicKey: "PA", AllowedIPs: "10.20.0.2/32", Rx: 10, Tx: 20, LastHandshake: now.Add(-40 * time.Second)}
	if _, err := s.ApplySample(ctx, iface.ID, now.Add(-15*time.Second), []PeerSample{base}, OnlineWindow); err != nil {
		t.Fatal(err)
	}
	next := base
	next.Rx, next.Tx, next.LastHandshake = 110, 220, now.Add(-30*time.Second)
	if _, err := s.ApplySample(ctx, iface.ID, now, []PeerSample{next}, OnlineWindow); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeviceByID(ctx, devID); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		f    UserFilter
		want int
	}{
		{"все", UserFilter{}, 3},
		{"поиск по имени", UserFilter{Query: "анн"}, 1},
		{"поиск по заметке", UserFilter{Query: "работа"}, 1},
		{"поиск без совпадений", UserFilter{Query: "%"}, 0},
		{"только активные", UserFilter{Status: "active"}, 2},
		{"только выключенные", UserFilter{Status: "disabled"}, 1},
		{"самообслуживание", UserFilter{SelfService: true}, 1},
		{"онлайн", UserFilter{Online: true}, 1},
	}
	for _, c := range cases {
		got, total, err := s.Users(ctx, c.f)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if total != c.want || len(got) != c.want {
			t.Fatalf("%s: получено %d строк (total %d), ожидалось %d", c.name, len(got), total, c.want)
		}
	}
	// Пагинация.
	page, total, _ := s.Users(ctx, UserFilter{Limit: 2, Offset: 2})
	if total != 3 || len(page) != 1 || page[0].Name != "Виктор" {
		t.Fatalf("пагинация: %+v (total %d)", page, total)
	}
	// Счётчики в списке.
	list, _, _ := s.Users(ctx, UserFilter{Query: "Анна"})
	if len(list) != 1 || list[0].Devices != 1 || list[0].Online != 1 || list[0].Rx24 != 100 || list[0].Tx24 != 200 {
		t.Fatalf("счётчики Анны: %+v", list)
	}
}
