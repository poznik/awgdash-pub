package web

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/poznik/awgdash-pub/internal/awgtest"
	"github.com/poznik/awgdash-pub/internal/clientconf"
	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/store"
)

// Передача устройства другому человеку из его карточки (FR-3.9).
func TestDeviceMoveFromPage(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	iface, err := e.hub.Interface(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	nik, _, err := e.store.CreateUser(ctx, store.User{Name: "Nik", MaxDevices: 5})
	if err != nil {
		t.Fatal(err)
	}
	poz, _, err := e.store.CreateUser(ctx, store.User{Name: "Alex Doe", MaxDevices: 5})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: nik, InterfaceID: iface.ID, Name: "n1"})
	if err != nil {
		t.Fatal(err)
	}
	csrf := e.login(t)

	_, body := e.get(t, "/devices/"+itoa(dev.ID))
	for _, want := range []string{`data-open="#move"`, `action="/devices/` + itoa(dev.ID) + `/move"`, "Alex Doe"} {
		if !strings.Contains(body, want) {
			t.Fatalf("на странице устройства нет %q", want)
		}
	}
	if strings.Contains(body, `<option value="`+itoa(nik)+`">`) {
		t.Fatal("нынешний владелец не должен предлагаться в списке")
	}

	resp, _ := e.post(t, "/devices/"+itoa(dev.ID)+"/move", url.Values{"csrf": {csrf}, "user_id": {itoa(poz)}})
	if resp.StatusCode != 303 {
		t.Fatalf("перенос: %d", resp.StatusCode)
	}
	fresh, err := e.store.DeviceByID(ctx, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.UserID != poz || fresh.PublicKey != dev.PublicKey || fresh.Address != dev.Address {
		t.Fatalf("устройство после переноса: %+v", fresh)
	}
	if msg, bad := flashOf(t, resp.Header.Get("Location")); bad != "" || !strings.Contains(msg, "теперь у «Alex Doe»") {
		t.Fatalf("панель не сказала, что получилось: ok=%q err=%q", msg, bad)
	}
}

// Объединение людей из карточки: устройства уезжают, опустевший удаляется (FR-2.7).
func TestUserMergeFromCard(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	iface, err := e.hub.Interface(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	nik, _, err := e.store.CreateUser(ctx, store.User{Name: "Nik", MaxDevices: 5})
	if err != nil {
		t.Fatal(err)
	}
	poz, _, err := e.store.CreateUser(ctx, store.User{Name: "Alex Doe", MaxDevices: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: poz, InterfaceID: iface.ID, Name: "n1"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"n1", "n2"} {
		if _, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: nik, InterfaceID: iface.ID, Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	csrf := e.login(t)

	_, body := e.get(t, "/users/"+itoa(nik))
	for _, want := range []string{`data-open="#merge"`, `action="/users/` + itoa(nik) + `/merge"`, "удалить «Nik» после переноса"} {
		if !strings.Contains(body, want) {
			t.Fatalf("в карточке нет %q", want)
		}
	}

	// Без флажка лимит получателя (одно устройство) не пускает перенос двух.
	resp, _ := e.post(t, "/users/"+itoa(nik)+"/merge", url.Values{"csrf": {csrf}, "user_id": {itoa(poz)}})
	if resp.StatusCode != 303 {
		t.Fatalf("объединение: %d", resp.StatusCode)
	}
	if _, bad := flashOf(t, resp.Header.Get("Location")); !strings.Contains(bad, "лимит") {
		t.Fatalf("панель обязана объяснить отказ по лимиту: %q", bad)
	}
	left, err := e.store.DevicesByUser(ctx, nik)
	if err != nil || len(left) != 2 {
		t.Fatalf("после отказа устройства остаются на месте: %d (%v)", len(left), err)
	}

	resp, _ = e.post(t, "/users/"+itoa(nik)+"/merge", url.Values{
		"csrf": {csrf}, "user_id": {itoa(poz)}, "raise_limit": {"1"}, "delete_emptied": {"1"}})
	if resp.StatusCode != 303 {
		t.Fatalf("объединение: %d", resp.StatusCode)
	}
	devs, err := e.store.DevicesByUser(ctx, poz)
	if err != nil {
		t.Fatal(err)
	}
	if len(devs) != 3 {
		t.Fatalf("у получателя должно стать 3 устройства, стало %d", len(devs))
	}
	var names []string
	for _, d := range devs {
		names = append(names, d.Name)
	}
	if !strings.Contains(strings.Join(names, ","), "n1 Nik") {
		t.Fatalf("занятое имя должно было получить суффикс: %v", names)
	}
	gone, err := e.store.UserByID(ctx, nik)
	if err != nil || gone.DeletedAt.IsZero() {
		t.Fatalf("опустевший должен уйти в корзину: %+v (%v)", gone, err)
	}
	if msg, bad := flashOf(t, resp.Header.Get("Location")); bad != "" || !strings.Contains(msg, "«Nik» удалён") {
		t.Fatalf("панель не отчиталась об удалении: ok=%q err=%q", msg, bad)
	}
}

// Привязка ничьего пира без имени: панель подставляет своё и оно обязано проходить проверку
// имени (FR-3.8). Прежде подставлялось «пир aBcDeFgH…wXyZ» с многоточием, и кнопка не работала.
func TestPeerAdoptWithoutName(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	csrf := e.login(t)
	id, _, err := e.store.CreateUser(ctx, store.User{Name: "Хозяин", MaxDevices: 5})
	if err != nil {
		t.Fatal(err)
	}
	// Пир становится «ничьим» после обхода: панель видит его в рантайме, но владельца не знает.
	if _, err := e.store.ApplySample(ctx, e.iface.ID, time.Now(), []store.PeerSample{
		{PublicKey: awgtest.KeyA, AllowedIPs: "10.20.0.2/32"},
	}, store.OnlineWindow); err != nil {
		t.Fatal(err)
	}

	// Пока пир ничей, в форме есть поле имени с подсказкой — тем самым именем, что подставится.
	_, page := e.get(t, "/interfaces/awg-t0")
	if !strings.Contains(page, `name="name"`) || !strings.Contains(page, "пир ") {
		t.Fatal("в форме привязки нет поля имени с подсказкой")
	}

	loc := e.action(t, "/interfaces/awg-t0/adopt", url.Values{
		"public_key": {awgtest.KeyA}, "user_id": {itoa(id)},
	}, csrf)
	if msg, bad := flashOf(t, loc); bad != "" || !strings.Contains(msg, "привязан") {
		t.Fatalf("привязка без имени: ok=%q err=%q", msg, bad)
	}
	devs, err := e.store.DevicesByUser(ctx, id)
	if err != nil || len(devs) != 1 {
		t.Fatalf("устройство не появилось: %d (%v)", len(devs), err)
	}
	if err := store.ValidDeviceName(devs[0].Name); err != nil {
		t.Fatalf("имя %q не проходит проверку: %v", devs[0].Name, err)
	}
	if !strings.HasPrefix(devs[0].Name, "пир ") {
		t.Fatalf("имя по умолчанию: %q", devs[0].Name)
	}

}

// Устройства человека разложены по серверам: живые серверы по названию, выведенный — в конец.
// Вперемешку карточки читаются как один список, где чужой сервер виден только по адресу.
func TestUserDevicesGroupedByServer(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	local, err := e.hub.Interface(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	kz, err := e.store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", NodePort: 10089, Country: "KZ"})
	if err != nil {
		t.Fatal(err)
	}
	kzIface, err := e.store.UpsertInterface(ctx, kz.ID, "awg-kz", store.InterfaceFacts{
		Subnet: "10.30.0.0/24", ServerAddress: "10.30.0.1/24", ListenPort: 443, MTU: 1280, IsAWG: true})
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := e.store.CreateUser(ctx, store.User{Name: "Странник", MaxDevices: 5})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		iface int64
		name  string
	}{{local.ID, "Дома"}, {kzIface, "В поездке"}, {local.ID, "Ноут"}} {
		if _, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: id, InterfaceID: c.iface, Name: c.name}); err != nil {
			t.Fatal(err)
		}
	}
	e.login(t)

	_, body := e.get(t, "/users/"+itoa(id))
	de, kzPos := strings.Index(body, "Германия</span>"), strings.Index(body, "Казахстан</span>")
	if de < 0 || kzPos < 0 {
		t.Fatal("на карточке нет заголовков групп по серверам")
	}
	if de > kzPos {
		t.Fatal("группы идут не по алфавиту названий серверов")
	}
	if !strings.Contains(body, "2 устройства") || !strings.Contains(body, "1 устройство") {
		t.Fatal("в заголовке группы нет счётчика устройств")
	}
	// Устройства одного сервера лежат под своим заголовком, а не вперемешку.
	if home := strings.Index(body, ">Дома<"); home < de || home > kzPos {
		t.Fatalf("устройство de оказалось вне своей группы (de=%d, дома=%d, kz=%d)", de, home, kzPos)
	}

	// Выведенный сервер уходит в конец: его устройства уже не работают.
	if err := e.hub.RetireServer(ctx, kz.ID); err != nil {
		t.Fatal(err)
	}
	_, body = e.get(t, "/users/"+itoa(id))
	de, kzPos = strings.Index(body, "Германия</span>"), strings.Index(body, "Казахстан</span>")
	if kzPos < de {
		t.Fatal("выведенный сервер должен уходить в конец списка групп")
	}
	if !strings.Contains(body, "сервер выведен") {
		t.Fatal("в заголовке группы не сказано, что сервер выведен")
	}
}

// Форма адресов входа отдаёт поля параллельными списками label/host/port, и порядок в разметке
// решает, какая метка к какому адресу относится. Раскладка менялась (таблица на четыре колонки
// не влезала в боковую колонку и включала прокрутку), поэтому соответствие проверяется отдельно.
func TestInterfaceEndpointsSurviveFormLayout(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	csrf := e.login(t)

	_, page := e.get(t, "/interfaces/awg-t0")
	if strings.Contains(page, "<th>метка</th>") {
		t.Fatal("адреса входа снова свёрстаны таблицей — она не помещается в боковую колонку")
	}
	if !strings.Contains(page, `class="ep"`) {
		t.Fatal("в форме адресов нет строк .ep")
	}

	loc := e.action(t, "/interfaces/awg-t0/endpoints", url.Values{
		"label":   {"основной", "запасной порт"},
		"host":    {"vpn.example.com", "backup.example.com"},
		"port":    {"443", "8443"},
		"primary": {"0"},
	}, csrf)
	if _, bad := flashOf(t, loc); bad != "" {
		t.Fatalf("сохранение адресов: %q", bad)
	}
	iface, err := e.hub.Interface(ctx, e.iface.ID)
	if err != nil {
		t.Fatal(err)
	}
	got := clientconf.Endpoints(iface)
	if len(got) != 2 {
		t.Fatalf("адресов сохранилось %d", len(got))
	}
	if got[0].Label != "основной" || got[0].Host != "vpn.example.com" || got[0].Port != 443 || !got[0].Primary {
		t.Fatalf("первый адрес разъехался: %+v", got[0])
	}
	if got[1].Label != "запасной порт" || got[1].Host != "backup.example.com" || got[1].Port != 8443 {
		t.Fatalf("второй адрес разъехался: %+v", got[1])
	}
}

// Наблюдаемый интерфейс в портале не предлагается и не принимается: панель на нём пиров не
// пишет, поэтому самообслуживание выдало бы человеку конфиг, который никогда не подключится.
func TestPortalRefusesObservedInterface(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	kz, err := e.store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	observed, err := e.store.UpsertInterface(ctx, kz.ID, "awg-kz", store.InterfaceFacts{
		Subnet: "10.30.0.0/24", ServerAddress: "10.30.0.1/24", ListenPort: 443, MTU: 1280, IsAWG: true})
	if err != nil {
		t.Fatal(err)
	}
	// Свой интерфейс панель ведёт, чужой остаётся под наблюдением.
	if err := e.store.SetInterfaceMode(ctx, e.iface.ID, hub.ModeOwn); err != nil {
		t.Fatal(err)
	}
	u, token, err := e.store.CreateUser(ctx, store.User{Name: "Сам себе", SelfService: true, MaxDevices: 5})
	if err != nil {
		t.Fatal(err)
	}

	// Наблюдаемый сервер не упоминается вовсе, а форма добавления на месте: выбор из одного
	// варианта портал не показывает — выбирать не из чего.
	_, body := e.withHost(t, "portal.example.com", "/u/"+token)
	if strings.Contains(body, "Казахстан") || strings.Contains(body, "awg-kz") {
		t.Fatal("наблюдаемый сервер предложен человеку в портале")
	}
	if !strings.Contains(body, "Новое устройство") {
		t.Fatal("форма добавления устройства пропала")
	}

	// Подделанная форма отклоняется — список приходит от клиента, доверять ему нельзя.
	_, err = e.hub.PortalAddDevice(ctx, mustUser(t, e, u), "Телефон", "phone", observed, "test")
	if err == nil {
		t.Fatal("устройство на наблюдаемом интерфейсе создалось")
	}
	if !strings.Contains(err.Error(), "не выдаются") {
		t.Fatalf("отказ должен объяснять причину: %v", err)
	}
	// А на своём интерфейсе всё работает.
	if _, err := e.hub.PortalAddDevice(ctx, mustUser(t, e, u), "Телефон", "phone", e.iface.ID, "test"); err != nil {
		t.Fatalf("на своём интерфейсе устройство обязано заводиться: %v", err)
	}
}

func mustUser(t *testing.T, e *testEnv, id int64) store.User {
	t.Helper()
	u, err := e.store.UserByID(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
