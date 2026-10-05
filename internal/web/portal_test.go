package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/store"
)

// portalUser заводит пользователя с устройством и возвращает его токен.
func (e *testEnv) portalUser(t *testing.T, name string, selfService bool, devices int) (store.User, string) {
	t.Helper()
	ctx := context.Background()
	id, token, err := e.store.CreateUser(ctx, store.User{
		Name: name, SelfService: selfService, MaxDevices: 3, DefaultInterfaceID: e.iface.ID,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < devices; i++ {
		if _, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: id, InterfaceID: e.iface.ID, Name: "Устройство " + itoa(int64(i+1))}); err != nil {
			t.Fatal(err)
		}
	}
	u, err := e.store.UserByID(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	return u, token
}

// portalGet ходит на портал под его именем: на имени админки портала нет.
func (e *testEnv) portalGet(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	req.Host = "portal.example.com"
	return e.do(t, req)
}

func (e *testEnv) portalPost(t *testing.T, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+path, strings.NewReader(form.Encode()))
	req.Host = "portal.example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	return e.do(t, req)
}

func TestPortalPage(t *testing.T) {
	e := newEnv(t)
	_, token := e.portalUser(t, "Ирина", true, 2)

	resp, body := e.portalGet(t, "/u/"+token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("страница портала: %d", resp.StatusCode)
	}
	for _, want := range []string{"Ирина", "Устройство 1", "Устройство 2", "за месяц", "Новое устройство", "Как подключить"} {
		if !strings.Contains(body, want) {
			t.Fatalf("нет %q на странице портала", want)
		}
	}
	// Заголовки FR-5.3.
	for header, want := range map[string]string{
		"Cache-Control":   "no-store",
		"X-Robots-Tag":    "noindex",
		"Referrer-Policy": "no-referrer",
	} {
		if got := resp.Header.Get(header); !strings.Contains(got, want) {
			t.Fatalf("%s = %q, ожидалось %q", header, got, want)
		}
	}
	// Ни ключей, ни чужих данных.
	for _, bad := range []string{"PrivateKey", "$argon2id", "awgdash_session"} {
		if strings.Contains(body, bad) {
			t.Fatalf("на портале оказалось %q", bad)
		}
	}
	// FR-5.5: страница ≤ 40 КБ и приезжает одним запросом — ни внешних стилей, ни скриптов.
	if len(body) > 40*1024 {
		t.Fatalf("страница портала %d байт, бюджет 40 КБ", len(body))
	}
	// Значок вкладки встроен как data:, поэтому проверяем подгружаемые ресурсы поимённо:
	// стили, скрипты, шрифты и статику панели. Ссылки навигации портала к ним не относятся.
	for _, bad := range []string{`<link rel="stylesheet"`, "<script", `src="http`, "fonts.googleapis", "/static/"} {
		if strings.Contains(body, bad) {
			t.Fatalf("портал тянет внешний ресурс (%s)", bad)
		}
	}
	// Стили должны приезжать целиком: без них портал открывается голым HTML.
	for _, want := range []string{"--paper:", ".card {", "font-family: var(--body)"} {
		if !strings.Contains(body, want) {
			t.Fatalf("в странице нет правила стиля %q", want)
		}
	}
	t.Logf("страница портала: %.1f КБ", float64(len(body))/1024)
}

func TestPortalUnknownToken(t *testing.T) {
	e := newEnv(t)
	_, token := e.portalUser(t, "Ирина", false, 1)

	start := time.Now()
	resp, _ := e.portalGet(t, "/u/"+strings.Repeat("A", 43))
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("чужой токен: %d", resp.StatusCode)
	}
	// FR-5.3: ответ задержан, чтобы перебор был дорогим.
	if took := time.Since(start); took < portalTokenDelay {
		t.Fatalf("ответ без задержки: %v", took)
	}
	// Ответ на чужой токен неотличим от ответа на несуществующий путь.
	if resp.Header.Get("Content-Type") == "" && len(token) == 0 {
		t.Fatal("пустой ответ")
	}
	// Отключённому пользователю портал тоже не открывается.
	u, tok := e.portalUser(t, "Отключённый", true, 1)
	if err := e.store.SetUserStatus(context.Background(), u.ID, "disabled"); err != nil {
		t.Fatal(err)
	}
	if resp, _ := e.portalGet(t, "/u/"+tok); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("портал отключённого пользователя: %d", resp.StatusCode)
	}
}

func TestPortalHostSplit(t *testing.T) {
	e := newEnv(t)
	_, token := e.portalUser(t, "Ирина", false, 1)
	// На имени админки портала нет.
	resp, _ := e.withHost(t, "panel.example.com", "/u/"+token)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("портал открылся на имени админки: %d", resp.StatusCode)
	}
	// А на своём — открывается.
	if resp, _ := e.portalGet(t, "/u/"+token); resp.StatusCode != http.StatusOK {
		t.Fatalf("портал на своём имени: %d", resp.StatusCode)
	}
}

func TestPortalDeviceConfig(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u, token := e.portalUser(t, "Ирина", false, 1)
	devs, _ := e.store.DevicesByUser(ctx, u.ID)
	dev := devs[0]

	resp, body := e.portalGet(t, "/u/"+token+"/devices/"+itoa(dev.ID))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("страница устройства: %d", resp.StatusCode)
	}
	// FR-5.4: QR — inline SVG, скачивание — обычная ссылка, JS не нужен.
	if !strings.Contains(body, "<svg") || !strings.Contains(body, "Скачать .conf") {
		t.Fatal("нет QR или ссылки на файл")
	}
	if !strings.Contains(body, "Endpoint = vpn.example.com:443") {
		t.Fatal("в тексте конфига нет основного endpoint")
	}
	// Вариант endpoint переключается ссылкой.
	_, alt := e.portalGet(t, "/u/"+token+"/devices/"+itoa(dev.ID)+"?ep="+url.QueryEscape("запасной порт"))
	if !strings.Contains(alt, "Endpoint = vpn.example.com:8443") {
		t.Fatal("запасной порт не применился")
	}

	resp, file := e.portalGet(t, "/u/"+token+"/devices/"+itoa(dev.ID)+"/conf")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(file, "[Interface]") {
		t.Fatalf("файл конфига: %d %.40s", resp.StatusCode, file)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("Content-Disposition: %s", cd)
	}

	// Чужое устройство по прямой ссылке не открывается.
	other, otherToken := e.portalUser(t, "Пётр", false, 1)
	otherDevs, _ := e.store.DevicesByUser(ctx, other.ID)
	if resp, _ := e.portalGet(t, "/u/"+token+"/devices/"+itoa(otherDevs[0].ID)); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("чужое устройство отдано: %d", resp.StatusCode)
	}
	if resp, _ := e.portalGet(t, "/u/"+otherToken+"/devices/"+itoa(dev.ID)+"/conf"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("чужой конфиг отдан: %d", resp.StatusCode)
	}
}

func TestPortalSelfService(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u, token := e.portalUser(t, "Ирина", true, 1)

	// Добавление ведёт сразу на конфиг нового устройства.
	resp, _ := e.portalPost(t, "/u/"+token+"/devices", url.Values{"name": {"Ноутбук"}, "preset": {"phone"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("добавление: %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.Contains(loc, "/devices/") {
		t.Fatalf("после добавления: %s", loc)
	}
	devs, _ := e.store.DevicesByUser(ctx, u.ID)
	if len(devs) != 2 {
		t.Fatalf("устройств: %d", len(devs))
	}
	var added store.Device
	for _, d := range devs {
		if d.Name == "Ноутбук" {
			added = d
		}
	}
	if added.ID == 0 || added.CreatedBy != "user" {
		t.Fatalf("устройство пользователя: %+v", added)
	}
	// Действие записано в журнал от лица пользователя.
	entries, _ := e.store.Audit(ctx, store.AuditFilter{Actor: store.UserActor(u.ID)})
	if len(entries) == 0 {
		t.Fatal("действие пользователя не попало в журнал")
	}

	// Переименование.
	resp, _ = e.portalPost(t, "/u/"+token+"/devices/"+itoa(added.ID)+"/rename", url.Values{"name": {"Рабочий ноутбук"}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("переименование: %d", resp.StatusCode)
	}
	fresh, _ := e.store.DeviceByID(ctx, added.ID)
	if fresh.Name != "Рабочий ноутбук" {
		t.Fatalf("имя: %s", fresh.Name)
	}

	// Лимит: третье устройство влезает, четвёртое — нет.
	e.portalPost(t, "/u/"+token+"/devices", url.Values{"name": {"Планшет"}})
	resp, _ = e.portalPost(t, "/u/"+token+"/devices", url.Values{"name": {"Лишнее"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "err=") {
		t.Fatalf("лимит не сработал: %s", loc)
	}

	// Удаление — мягкое: администратор сможет вернуть.
	resp, _ = e.portalPost(t, "/u/"+token+"/devices/"+itoa(added.ID)+"/delete", url.Values{})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("удаление: %d", resp.StatusCode)
	}
	gone, err := e.store.DeviceByID(ctx, added.ID)
	if err != nil || gone.DeletedAt.IsZero() {
		t.Fatalf("устройство не в корзине: %+v, err = %v", gone, err)
	}
}

func TestPortalWithoutSelfService(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	u, token := e.portalUser(t, "Пётр", false, 1)

	_, body := e.portalGet(t, "/u/"+token)
	if strings.Contains(body, "Новое устройство") || strings.Contains(body, "Переименовать") {
		t.Fatal("без самообслуживания на странице есть формы изменения")
	}
	resp, _ := e.portalPost(t, "/u/"+token+"/devices", url.Values{"name": {"Тайком"}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "err=") {
		t.Fatalf("устройство создано без права: %s", loc)
	}
	devs, _ := e.store.DevicesByUser(ctx, u.ID)
	if len(devs) != 1 {
		t.Fatalf("устройств стало %d", len(devs))
	}
}

func TestPortalForeignFormRejected(t *testing.T) {
	e := newEnv(t)
	_, token := e.portalUser(t, "Ирина", true, 0)
	req, _ := http.NewRequest("POST", e.srv.URL+"/u/"+token+"/devices",
		strings.NewReader(url.Values{"name": {"Чужой сайт"}}.Encode()))
	req.Host = "portal.example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Origin", "https://зло.example")
	resp, _ := e.do(t, req)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("запрос с чужой страницы: %d", resp.StatusCode)
	}
}

func TestPortalRateLimit(t *testing.T) {
	e := newEnv(t)
	var last int
	for i := 0; i < portalRateLimit+2; i++ {
		resp, _ := e.portalGet(t, "/u/"+strings.Repeat("Z", 43))
		last = resp.StatusCode
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("после %d попыток ответ %d, ожидался 429", portalRateLimit+2, last)
	}
	// Настоящая ссылка тоже временно закрыта — перебор с этого адреса остановлен целиком.
	_, token := e.portalUser(t, "Ирина", false, 0)
	if resp, _ := e.portalGet(t, "/u/"+token); resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("ограничитель пропустил запрос: %d", resp.StatusCode)
	}
}

// Сервер выбирается у устройства: человек не привязан к серверу. По умолчанию доступны все
// серверы парка, ограничение появляется, только когда администратор отметил конкретные.
func TestPortalServerChoice(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	srv, err := e.store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	second, err := e.store.UpsertInterface(ctx, srv.ID, "awg-kz", store.InterfaceFacts{
		Subnet: "10.30.0.0/24", ServerAddress: "10.30.0.1/24", ListenPort: 443, MTU: 1280, IsAWG: true})
	if err != nil {
		t.Fatal(err)
	}

	// Портал предлагает только те интерфейсы, которыми панель владеет: на наблюдаемом пир
	// не встанет. Оба переводим в own — тест про выбор сервера, а не про режим.
	for _, id := range []int64{e.iface.ID, second} {
		if err := e.store.SetInterfaceMode(ctx, id, hub.ModeOwn); err != nil {
			t.Fatal(err)
		}
	}

	id, token, err := e.store.CreateUser(ctx, store.User{Name: "Портальный", SelfService: true, MaxDevices: 5})
	if err != nil {
		t.Fatal(err)
	}

	// Без ограничений видны оба сервера, и рядом с названием стоит флаг страны.
	_, body := e.withHost(t, "portal.example.com", "/u/"+token)
	if !strings.Contains(body, `name="interface_id"`) {
		t.Fatal("выбор сервера не показан")
	}
	for _, want := range []string{"Казахстан", "🇰🇿", "🇩🇪"} {
		if !strings.Contains(body, want) {
			t.Fatalf("в выборе нет %q", want)
		}
	}

	// Ограничение одним сервером убирает выбор.
	saved, _ := e.store.UserByID(ctx, id)
	saved.AllowedInterfaces = []int64{e.iface.ID}
	if err := e.store.UpdateUser(ctx, saved); err != nil {
		t.Fatal(err)
	}
	_, body = e.withHost(t, "portal.example.com", "/u/"+token)
	if strings.Contains(body, `type="radio" name="interface_id"`) {
		t.Fatal("выбор показан, хотя разрешён один сервер")
	}
	// Единственный вариант всё равно уходит скрытым полем: без него панель подставляла свой
	// сервер, и человек с одним разрешённым чужим сервером садился мимо ограничения.
	if !strings.Contains(body, `type="hidden" name="interface_id" value="`+itoa(e.iface.ID)+`"`) {
		t.Fatal("единственный разрешённый сервер не передаётся формой")
	}

	// Неразрешённый сервер отклоняется, даже если его подставили в форму.
	saved, _ = e.store.UserByID(ctx, id)
	if _, err := e.hub.PortalAddDevice(ctx, saved, "Чужой сервер", "phone", second, "127.0.0.1"); err == nil {
		t.Fatal("устройство создано на неразрешённом сервере")
	}
	// Без выбора устройство садится на сервер панели.
	dev, err := e.hub.PortalAddDevice(ctx, saved, "По умолчанию", "phone", 0, "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if dev.InterfaceID != e.iface.ID {
		t.Fatalf("устройство село на интерфейс %d, ожидался локальный %d", dev.InterfaceID, e.iface.ID)
	}
}
