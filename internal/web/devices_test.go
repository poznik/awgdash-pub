package web

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/store"
)

// Создание устройства: выбор сервера и типа кнопками, дополнительные настройки применяются
// сразу, после создания открывается конфиг.
func TestDeviceCreateFromForm(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	srv, err := e.store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	kzIf, err := e.store.UpsertInterface(ctx, srv.ID, "awg-kz", store.InterfaceFacts{
		Subnet: "10.30.0.0/24", ServerAddress: "10.30.0.1/24", ListenPort: 443, MTU: 1280, IsAWG: true})
	if err != nil {
		t.Fatal(err)
	}
	// Форма предлагает только интерфейсы под управлением панели (FR-3.1).
	if err := e.store.SetInterfaceMode(ctx, kzIf, hub.ModeOwn); err != nil {
		t.Fatal(err)
	}
	id, _, err := e.store.CreateUser(ctx, store.User{Name: "Форма", MaxDevices: 5})
	if err != nil {
		t.Fatal(err)
	}
	csrf := e.login(t)

	// Модалка отдаётся вместе со страницей пользователя, а ссылка ведёт на запасную страницу.
	_, body := e.get(t, "/users/"+itoa(id))
	for _, want := range []string{`<dialog class="modal"`, `data-modal="new-device"`, "🇰🇿 Казахстан", "Что это за устройство"} {
		if !strings.Contains(body, want) {
			t.Fatalf("в карточке пользователя нет %q", want)
		}
	}
	resp, body := e.get(t, "/users/"+itoa(id)+"/devices/new")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Новое устройство") {
		t.Fatalf("страница создания без JS не открылась: код %d", resp.StatusCode)
	}

	resp, _ = e.post(t, "/users/"+itoa(id)+"/devices/new", url.Values{
		"csrf": {csrf}, "name": {"Телефон"}, "preset": {"phone"},
		"interface_id": {itoa(e.iface.ID)}, "dns": {"9.9.9.9"}, "mtu": {"1380"},
	})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("создание вернуло %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "/config") {
		t.Fatalf("после создания ведёт на %q, ожидалась страница конфига", loc)
	}
	devices, err := e.store.DevicesByUser(ctx, id)
	if err != nil || len(devices) != 1 {
		t.Fatalf("устройства: %+v (err %v)", devices, err)
	}
	if devices[0].Overrides.DNS != "9.9.9.9" || devices[0].Overrides.MTU != 1380 {
		t.Fatalf("переопределения не применились: %+v", devices[0].Overrides)
	}
}

// Страница устройства должна уметь всё, что и карточка пользователя: правку, отключение,
// перевыпуск и удаление, — иначе с неё приходится уходить ради любого действия.
func TestDevicePageHasActions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	uid, _, err := e.store.CreateUser(ctx, store.User{Name: "Ирина", MaxDevices: 5, DefaultInterfaceID: e.iface.ID})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: uid, InterfaceID: e.iface.ID, Name: "Телефон"})
	if err != nil {
		t.Fatal(err)
	}
	csrf := e.login(t)

	_, page := e.get(t, "/devices/"+itoa(dev.ID))
	for _, want := range []string{
		`action="/devices/` + itoa(dev.ID) + `/update"`,
		`action="/devices/` + itoa(dev.ID) + `/status"`,
		`action="/devices/` + itoa(dev.ID) + `/rotate"`,
		`action="/devices/` + itoa(dev.ID) + `/delete"`,
		`data-open="#edit"`,
	} {
		if !strings.Contains(page, want) {
			t.Fatalf("на странице устройства нет %q", want)
		}
	}

	// Правка со страницы устройства действительно работает.
	if resp, body := e.post(t, "/devices/"+itoa(dev.ID)+"/update", url.Values{
		"csrf": {csrf}, "name": {"Телефон Ирины"}, "preset": {"phone"},
	}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("правка устройства: %d %s", resp.StatusCode, body)
	}
	got, _ := e.store.DeviceByID(ctx, dev.ID)
	if got.Name != "Телефон Ирины" {
		t.Fatalf("имя не сохранилось: %q", got.Name)
	}
}

// Форма создания показывает то, что панель подставит сама: «как на интерфейсе» заставляло идти
// на страницу интерфейса и сверять, а AllowedIPs по типу устройства там не увидеть вовсе.
func TestDeviceFormShowsRealDefaults(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	if err := e.store.SetInterfaceDefaults(ctx, e.iface.ID, "10.40.0.1", 21, "0.0.0.0/0"); err != nil {
		t.Fatal(err)
	}
	id, _, err := e.store.CreateUser(ctx, store.User{Name: "Подсказки", MaxDevices: 5})
	if err != nil {
		t.Fatal(err)
	}
	e.login(t)

	_, body := e.get(t, "/users/"+itoa(id)+"/devices/new")
	if strings.Contains(body, "как на интерфейсе") {
		t.Fatal("в форме снова стоит «как на интерфейсе» вместо значения")
	}
	// Без JS форма показывает значения интерфейса, отмеченного по умолчанию, и типа «телефон».
	for _, want := range []string{`placeholder="10.40.0.1"`, `placeholder="1280"`, `placeholder="21"`, `placeholder="0.0.0.0/0"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("в форме нет %s", want)
		}
	}
	// Роутеру достаются свои значения: keepalive 25 и список, посчитанный по подсети (FR-4.3).
	for _, want := range []string{`data-ka-router="25"`, `data-ip-router="интернет без локальных сетей, плюс 10.20.0.0/16"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("в форме нет %s", want)
		}
	}

	// Пустое умолчание — законное состояние: подсказка говорит, что строки в конфиге не будет.
	if err := e.store.SetInterfaceDefaults(ctx, e.iface.ID, "", 0, "0.0.0.0/0"); err != nil {
		t.Fatal(err)
	}
	_, body = e.get(t, "/users/"+itoa(id)+"/devices/new")
	for _, want := range []string{`placeholder="без строки DNS"`, `placeholder="без keepalive"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("в форме нет %s", want)
		}
	}

	// Форма правки показывает то же самое, причём для роутера — его собственные значения:
	// иначе рядом стояли бы две формы с разными ответами на один вопрос.
	if err := e.store.SetInterfaceDefaults(ctx, e.iface.ID, "10.40.0.1", 21, "0.0.0.0/0"); err != nil {
		t.Fatal(err)
	}
	dev, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: id, InterfaceID: e.iface.ID, Name: "Роутер дома", Preset: store.PresetRouter})
	if err != nil {
		t.Fatal(err)
	}
	_, body = e.get(t, "/devices/"+itoa(dev.ID))
	for _, want := range []string{`placeholder="10.40.0.1"`, `placeholder="1280"`, `placeholder="25"`, `placeholder="интернет без локальных сетей, плюс 10.20.0.0/16"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("на странице устройства нет %s", want)
		}
	}
}

// Счётчики ядра серверные: transfer-rx — то, что интерфейс принял от пира, transfer-tx — то,
// что отправил ему. Человеку это надо показывать наоборот: «скачано» — отправленное сервером.
// Тест закрепляет направление, чтобы стрелки снова не перевернулись.
func TestTrafficIsShownFromClientSide(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	now := time.Now()
	uid, token, err := e.store.CreateUser(ctx, store.User{Name: "Марина", MaxDevices: 5, SelfService: true, DefaultInterfaceID: e.iface.ID})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: uid, InterfaceID: e.iface.ID, Name: "Телефон"})
	if err != nil {
		t.Fatal(err)
	}
	res, err := e.store.DB().ExecContext(ctx, `INSERT INTO peers (interface_id, public_key, allowed_ips, in_conf, device_id, first_seen_at, last_seen_at)
		VALUES (?, ?, ?, 1, ?, ?, ?)`, e.iface.ID, dev.PublicKey, dev.Address, dev.ID, now.Add(-time.Hour).Unix(), now.Unix())
	if err != nil {
		t.Fatal(err)
	}
	peerID, _ := res.LastInsertId()
	// Сервер принял от устройства 1 МБ и отправил ему 9 МБ: человек скачал девять, отдал один.
	const up, down = 1_000_000, 9_000_000
	if _, err := e.store.DB().ExecContext(ctx, `INSERT INTO traffic_raw (ts, peer_id, rx, tx) VALUES (?, ?, ?, ?)`,
		now.Add(-time.Minute).Unix(), peerID, up, down); err != nil {
		t.Fatal(err)
	}
	e.login(t)

	_, body := e.get(t, "/users/"+itoa(uid))
	if !strings.Contains(body, "Скачано</span><span class=\"meter__val\">"+fmtBytes(down)+" ↓") {
		t.Fatalf("в карточке устройства скачанное показано не тем числом:\n%s", cut(body, "Скачано", 160))
	}
	if !strings.Contains(body, "Отдано</span><span class=\"meter__val\">"+fmtBytes(up)+" ↑") {
		t.Fatalf("в карточке устройства отданное показано не тем числом:\n%s", cut(body, "Отдано", 160))
	}

	// Портал говорит людям то же самое.
	_, portal := e.portalGet(t, "/u/"+token)
	if !strings.Contains(portal, "↓"+fmtBytes(down)+" ↑"+fmtBytes(up)) {
		t.Fatalf("в портале трафик перевёрнут:\n%s", cut(portal, "за сутки", 120))
	}
}

// cut — кусок страницы вокруг подстроки, чтобы падение теста было читаемым.
func cut(body, anchor string, n int) string {
	i := strings.Index(body, anchor)
	if i < 0 {
		return "(«" + anchor + "» на странице нет)"
	}
	end := i + n
	if end > len(body) {
		end = len(body)
	}
	return body[i:end]
}

// Наблюдаемый сервер не показывается в выборе «через какой сервер» — ни в модалке, ни на
// запасной странице (FR-3.1): пир там не встанет. В настройках доступа человека он остаётся
// виден, пока отмечен, иначе сохранение формы молча сняло бы ограничение.
func TestObservedServerIsNotOfferedForDevice(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	kz, err := e.store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	// Служебный туннель под наблюдением — такой есть на каждой машине живого парка.
	hubIf, err := e.store.UpsertInterface(ctx, kz.ID, "awg-hub", store.InterfaceFacts{
		Subnet: "10.100.0.8/30", ServerAddress: "10.100.0.9/30", ListenPort: 443, MTU: 1280, IsAWG: true})
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := e.store.CreateUser(ctx, store.User{Name: "Пётр", MaxDevices: 5})
	if err != nil {
		t.Fatal(err)
	}
	e.login(t)

	for _, path := range []string{"/users/" + itoa(id), "/users/" + itoa(id) + "/devices/new"} {
		_, body := e.get(t, path)
		if strings.Contains(body, "awg-hub") {
			t.Fatalf("%s: наблюдаемый интерфейс предлагается в форме создания устройства", path)
		}
	}

	// Тот же интерфейс, уже разрешённый человеку, из настроек доступа не исчезает: иначе
	// сохранение карточки превратило бы ограничение в «любой сервер».
	u, err := e.store.UserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	u.AllowedInterfaces = []int64{e.iface.ID, hubIf}
	if err := e.store.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	_, body := e.get(t, "/users/"+itoa(id))
	if !strings.Contains(body, `value="`+itoa(hubIf)+`" checked`) {
		t.Fatal("отмеченный наблюдаемый интерфейс пропал из настроек доступа")
	}
}

// Форма создания: имя идёт первым полем, открывается с фокусом в нём и пустым — то, что панель
// подставит сама, показано серым. Раньше имя стояло третьим и было вписано в поле значением,
// поэтому своё название приходилось писать поверх выделенного, а выделение мышью с выходом за
// край формы закрывало модалку.
func TestDeviceFormNameGoesFirstAndStaysEmpty(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	id, _, err := e.store.CreateUser(ctx, store.User{Name: "Анна", MaxDevices: 5})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: id, InterfaceID: e.iface.ID, Name: "Ноутбук",
		Preset: store.PresetPhone, CreatedBy: "admin", Actor: store.ActorAdmin}); err != nil {
		t.Fatal(err)
	}
	e.login(t)

	for _, path := range []string{"/users/" + itoa(id), "/users/" + itoa(id) + "/devices/new"} {
		_, body := e.get(t, path)
		form := body[strings.Index(body, `<form class="modal__form"`):]
		if i := strings.Index(form, "</form>"); i > 0 {
			form = form[:i]
		}
		name := strings.Index(form, `name="name"`)
		if name < 0 {
			t.Fatalf("%s: в форме нет поля имени", path)
		}
		if pick := strings.Index(form, `<fieldset class="pick"`); pick >= 0 && pick < name {
			t.Fatalf("%s: поле имени идёт после выбора кнопками", path)
		}
		if !strings.Contains(form, `placeholder="Устройство 2" maxlength="32" autofocus`) {
			t.Fatalf("%s: имя по умолчанию не показано серым и без фокуса", path)
		}
		if strings.Contains(form, `name="name" value=`) {
			t.Fatalf("%s: имя по умолчанию вписано в поле", path)
		}
	}

	// Пустое поле не мешает отправке: имя подставит сервер.
	csrf := e.login(t)
	loc := e.action(t, "/users/"+itoa(id)+"/devices/new", url.Values{"name": {""}}, csrf)
	if _, errMsg := flashOf(t, loc); errMsg != "" {
		t.Fatalf("создание без имени: %s", errMsg)
	}
	list, err := e.store.DevicesByUser(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, d := range list {
		got = append(got, d.Name)
	}
	if !slices.Contains(got, "Устройство 2") {
		t.Fatalf("устройства пользователя: %v, ожидалось «Устройство 2»", got)
	}
}
