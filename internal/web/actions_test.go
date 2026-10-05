package web

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/poznik/awgdash-pub/internal/auth"
	"github.com/poznik/awgdash-pub/internal/awgtest"
	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/store"
)

// action отправляет форму и возвращает адрес, куда панель отправила после действия.
func (e *testEnv) action(t *testing.T, path string, form url.Values, csrf string) string {
	t.Helper()
	form.Set("csrf", csrf)
	resp, body := e.post(t, path, form)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("%s: %d %s", path, resp.StatusCode, body)
	}
	return resp.Header.Get("Location")
}

// flashOf вытаскивает сообщение из адреса редиректа.
func flashOf(t *testing.T, location string) (ok, fail string) {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get("ok"), u.Query().Get("err")
}

func TestUserLifecycleThroughUI(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	csrf := e.login(t)

	// Создание.
	loc := e.action(t, "/users/new", url.Values{"name": {"Ирина"}, "note": {"семья"}, "max_devices": {"3"}, "self_service": {"on"}}, csrf)
	if msg, bad := flashOf(t, loc); bad != "" || !strings.Contains(msg, "создан") {
		t.Fatalf("создание: ok=%q err=%q", msg, bad)
	}
	u, err := e.store.UserByName(ctx, "Ирина")
	if err != nil {
		t.Fatal(err)
	}
	if !u.SelfService || u.MaxDevices != 3 || u.Token == "" {
		t.Fatalf("пользователь: %+v", u)
	}
	id := itoa(u.ID)

	// Правка.
	e.action(t, "/users/"+id+"/update", url.Values{"name": {"Ирина С."}, "note": {"семья"}, "max_devices": {"5"}}, csrf)
	u, _ = e.store.UserByID(ctx, u.ID)
	if u.Name != "Ирина С." || u.MaxDevices != 5 || u.SelfService {
		t.Fatalf("после правки: %+v", u)
	}

	// Перевыпуск ссылки гасит прежнюю.
	old := u.Token
	e.action(t, "/users/"+id+"/link", url.Values{}, csrf)
	if _, err := e.store.UserByToken(ctx, old); err == nil {
		t.Fatal("прежняя ссылка осталась рабочей")
	}

	// Отключение и включение.
	e.action(t, "/users/"+id+"/status", url.Values{"status": {"disabled"}}, csrf)
	if u, _ = e.store.UserByID(ctx, u.ID); !u.Disabled() {
		t.Fatal("пользователь не отключён")
	}
	e.action(t, "/users/"+id+"/status", url.Values{"status": {"active"}}, csrf)
	if u, _ = e.store.UserByID(ctx, u.ID); u.Disabled() {
		t.Fatal("пользователь не включён обратно")
	}

	// Удаление и восстановление.
	e.action(t, "/users/"+id+"/delete", url.Values{}, csrf)
	if u, _ = e.store.UserByID(ctx, u.ID); u.DeletedAt.IsZero() {
		t.Fatal("пользователь не в корзине")
	}
	e.action(t, "/users/"+id+"/restore", url.Values{}, csrf)
	if u, _ = e.store.UserByID(ctx, u.ID); !u.DeletedAt.IsZero() {
		t.Fatal("пользователь не восстановлен")
	}
}

func TestDeviceLifecycleThroughUI(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	csrf := e.login(t)
	e.action(t, "/users/new", url.Values{"name": {"Анна"}, "interface_id": {itoa(e.iface.ID)}}, csrf)
	u, _ := e.store.UserByName(ctx, "Анна")
	uid := itoa(u.ID)

	// Создание ведёт сразу на конфиг.
	loc := e.action(t, "/users/"+uid+"/devices/new", url.Values{"name": {"Телефон"}, "preset": {"phone"}}, csrf)
	if !strings.Contains(loc, "/config") {
		t.Fatalf("после создания устройства: %s", loc)
	}
	devs, _ := e.store.DevicesByUser(ctx, u.ID)
	if len(devs) != 1 || devs[0].Name != "Телефон" || devs[0].PrivateKey == "" {
		t.Fatalf("устройство: %+v", devs)
	}
	dev := devs[0]
	did := itoa(dev.ID)

	// Правка: пресет и переопределения.
	e.action(t, "/devices/"+did+"/update", url.Values{"name": {"Телефон Ирины"}, "preset": {"router"}, "dns": {"9.9.9.9"}, "mtu": {"1400"}}, csrf)
	dev, _ = e.store.DeviceByID(ctx, dev.ID)
	if dev.Name != "Телефон Ирины" || dev.Preset != store.PresetRouter || dev.Overrides.DNS != "9.9.9.9" || dev.Overrides.MTU != 1400 {
		t.Fatalf("после правки: %+v", dev)
	}
	_, page := e.get(t, "/devices/"+did+"/config")
	if !strings.Contains(page, "DNS = 9.9.9.9") || !strings.Contains(page, "MTU = 1400") {
		t.Fatal("переопределения не попали в конфиг")
	}

	// Перевыпуск ключей: адрес тот же, ключ другой.
	before := dev
	e.action(t, "/devices/"+did+"/rotate", url.Values{}, csrf)
	dev, _ = e.store.DeviceByID(ctx, dev.ID)
	if dev.PublicKey == before.PublicKey || dev.Address != before.Address {
		t.Fatalf("после перевыпуска: было %s/%s, стало %s/%s", before.PublicKey, before.Address, dev.PublicKey, dev.Address)
	}

	// Отключение, удаление, восстановление.
	e.action(t, "/devices/"+did+"/status", url.Values{"status": {"disabled"}}, csrf)
	if dev, _ = e.store.DeviceByID(ctx, dev.ID); dev.Status != "disabled" {
		t.Fatalf("статус: %s", dev.Status)
	}
	// Устройство перед удалением уже отключено — пир снимается второй раз, и это норма:
	// настоящий awg на снятие отсутствующего пира отвечает молча.
	if _, errMsg := flashOf(t, e.action(t, "/devices/"+did+"/delete", url.Values{}, csrf)); errMsg != "" {
		t.Fatalf("удаление отключённого устройства: %s", errMsg)
	}
	if dev, _ = e.store.DeviceByID(ctx, dev.ID); dev.DeletedAt.IsZero() {
		t.Fatal("устройство не в корзине")
	}
	e.action(t, "/devices/"+did+"/restore", url.Values{}, csrf)
	if dev, _ = e.store.DeviceByID(ctx, dev.ID); !dev.DeletedAt.IsZero() || dev.Status != "disabled" {
		t.Fatalf("после восстановления: %+v", dev)
	}
}

func TestDeviceLimitShowsError(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	csrf := e.login(t)
	e.action(t, "/users/new", url.Values{"name": {"Лимит"}, "max_devices": {"1"}, "interface_id": {itoa(e.iface.ID)}}, csrf)
	u, _ := e.store.UserByName(ctx, "Лимит")
	uid := itoa(u.ID)

	e.action(t, "/users/"+uid+"/devices/new", url.Values{"name": {"Первое"}}, csrf)
	loc := e.action(t, "/users/"+uid+"/devices/new", url.Values{"name": {"Второе"}}, csrf)
	_, bad := flashOf(t, loc)
	if !strings.Contains(bad, "лимит") {
		t.Fatalf("ожидалась ошибка про лимит, получено: %q", bad)
	}
	devs, _ := e.store.DevicesByUser(ctx, u.ID)
	if len(devs) != 1 {
		t.Fatalf("устройств: %d", len(devs))
	}
}

func TestInterfaceModeAndReconcileThroughUI(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	csrf := e.login(t)

	// Пиры интерфейса ничьи — переход в own отклоняется с объяснением.
	if _, err := e.store.ApplySample(ctx, e.iface.ID, time.Now(), []store.PeerSample{
		{PublicKey: awgtest.KeyA, AllowedIPs: "10.20.0.2/32"},
		{PublicKey: awgtest.KeyB, AllowedIPs: "10.20.0.3/32"},
	}, store.OnlineWindow); err != nil {
		t.Fatal(err)
	}
	loc := e.action(t, "/interfaces/awg-t0/mode", url.Values{"mode": {"own"}}, csrf)
	_, bad := flashOf(t, loc)
	if !strings.Contains(bad, "не готов") {
		t.Fatalf("ожидался отказ, получено: %q", bad)
	}
	_, page := e.get(t, "/interfaces/awg-t0")
	if !strings.Contains(page, "без владельца") || !strings.Contains(page, "Привязать") {
		t.Fatal("на странице нет формы привязки ничьего пира")
	}

	// Привязываем пиры к людям — тогда переход разрешён.
	e.action(t, "/users/new", url.Values{"name": {"Анна"}, "interface_id": {itoa(e.iface.ID)}}, csrf)
	u, _ := e.store.UserByName(ctx, "Анна")
	for i, key := range []string{awgtest.KeyA, awgtest.KeyB} {
		loc := e.action(t, "/interfaces/awg-t0/adopt", url.Values{
			"public_key": {key}, "user_id": {itoa(u.ID)}, "name": {"Старое " + itoa(int64(i+1))},
		}, csrf)
		if _, bad := flashOf(t, loc); bad != "" {
			t.Fatalf("привязка пира: %q", bad)
		}
	}
	loc = e.action(t, "/interfaces/awg-t0/mode", url.Values{"mode": {"own"}}, csrf)
	if msg, bad := flashOf(t, loc); bad != "" || !strings.Contains(msg, "own") {
		t.Fatalf("переход в own: ok=%q err=%q", msg, bad)
	}
	iface, _ := e.hub.Interface(ctx, e.iface.ID)
	if iface.Mode != hub.ModeOwn {
		t.Fatalf("режим: %s", iface.Mode)
	}

	// Reconcile ничего не меняет: панель и интерфейс уже сходятся.
	loc = e.action(t, "/interfaces/awg-t0/reconcile", url.Values{}, csrf)
	if msg, bad := flashOf(t, loc); bad != "" || !strings.Contains(msg, "совпадает") {
		t.Fatalf("reconcile: ok=%q err=%q", msg, bad)
	}
	// И обратно в observe — всегда можно.
	loc = e.action(t, "/interfaces/awg-t0/mode", url.Values{"mode": {"observe"}}, csrf)
	if msg, _ := flashOf(t, loc); !strings.Contains(msg, "observe") {
		t.Fatalf("возврат в observe: %q", msg)
	}
}

func TestTOTPSetupThroughUI(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	csrf := e.login(t)

	// Готовим секрет: он показывается QR-кодом, но второй фактор ещё выключен.
	e.action(t, "/settings/totp/new", url.Values{}, csrf)
	admin, _ := e.store.AdminByID(ctx, e.admin.ID)
	if admin.TOTPSecret == "" || admin.TOTPEnabled {
		t.Fatalf("после подготовки: %+v", admin)
	}
	_, page := e.get(t, "/settings")
	if !strings.Contains(page, "<svg") || !strings.Contains(page, admin.TOTPSecret) {
		t.Fatal("на странице нет QR и секрета")
	}

	// Неверный код не включает.
	loc := e.action(t, "/settings/totp/enable", url.Values{"code": {"000000"}}, csrf)
	if _, bad := flashOf(t, loc); !strings.Contains(bad, "не подошёл") {
		t.Fatalf("неверный код: %q", bad)
	}
	if admin, _ = e.store.AdminByID(ctx, e.admin.ID); admin.TOTPEnabled {
		t.Fatal("второй фактор включён неверным кодом")
	}

	// Верный код включает, и следующий вход требует его.
	code, err := totp.GenerateCode(admin.TOTPSecret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e.action(t, "/settings/totp/enable", url.Values{"code": {code}}, csrf)
	if admin, _ = e.store.AdminByID(ctx, e.admin.ID); !admin.TOTPEnabled {
		t.Fatal("второй фактор не включился")
	}
	_, page = e.get(t, "/settings")
	if strings.Contains(page, admin.TOTPSecret) {
		t.Fatal("после включения секрет всё ещё показывается")
	}
	if !auth.VerifyTOTP(admin.TOTPSecret, code, time.Now()) {
		t.Fatal("сохранён не тот секрет")
	}

	// Выключение возвращает вход по одному паролю.
	e.action(t, "/settings/totp/disable", url.Values{}, csrf)
	if admin, _ = e.store.AdminByID(ctx, e.admin.ID); admin.TOTPEnabled || admin.TOTPSecret != "" {
		t.Fatalf("после выключения: %+v", admin)
	}
}

func TestRevokeOtherSessions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	csrf := e.login(t)
	// Второй вход «с другого устройства».
	if _, err := e.store.CreateSession(ctx, e.admin.ID, "10.9.9.9", "телефон"); err != nil {
		t.Fatal(err)
	}
	if list, _ := e.store.Sessions(ctx, e.admin.ID); len(list) != 2 {
		t.Fatalf("сессий до закрытия: %d", len(list))
	}
	loc := e.action(t, "/settings/sessions/revoke", url.Values{}, csrf)
	if msg, bad := flashOf(t, loc); bad != "" || !strings.Contains(msg, "1") {
		t.Fatalf("закрытие сессий: ok=%q err=%q", msg, bad)
	}
	list, _ := e.store.Sessions(ctx, e.admin.ID)
	if len(list) != 1 {
		t.Fatalf("сессий осталось: %d", len(list))
	}
	// Текущая жива: страница по-прежнему открывается.
	if resp, _ := e.get(t, "/settings"); resp.StatusCode != http.StatusOK {
		t.Fatal("закрыли собственную сессию")
	}
}

// Панель стоит за обратным прокси: тот подменяет Host на localhost:10088, а браузер шлёт Origin
// с внешним именем. Раньше на этом падало любое действие в панели — «запрос пришёл с чужой страницы».
func TestActionsBehindReverseProxy(t *testing.T) {
	e := newEnv(t)
	csrf := e.login(t)

	post := func(t *testing.T, origin, xfh, site string) int {
		t.Helper()
		form := url.Values{"csrf": {csrf}, "name": {"Из-за прокси"}, "max_devices": {"3"}}
		req, _ := http.NewRequest("POST", e.srv.URL+"/users/new", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if xfh != "" {
			req.Header.Set("X-Forwarded-Host", xfh)
		}
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		u, _ := url.Parse(e.srv.URL)
		for _, c := range e.client.Jar.Cookies(u) {
			req.AddCookie(c)
		}
		resp, _ := e.do(t, req)
		return resp.StatusCode
	}

	// Так выглядит нажатие кнопки в браузере через обратный прокси.
	if code := post(t, "https://panel.example.com", "panel.example.com", "same-origin"); code != http.StatusSeeOther {
		t.Fatalf("действие через прокси: %d, ожидался 303", code)
	}
	// Даже если прокси не передаёт X-Forwarded-Host, внешнее имя известно панели из настроек.
	if code := post(t, "https://panel.example.com", "", "same-origin"); code != http.StatusSeeOther {
		t.Fatalf("действие без X-Forwarded-Host: %d, ожидался 303", code)
	}
	// Локальная работа через ssh -L.
	if code := post(t, "http://localhost:10088", "", ""); code != http.StatusSeeOther {
		t.Fatalf("действие через туннель: %d, ожидался 303", code)
	}
	// А чужая страница по-прежнему получает отказ.
	if code := post(t, "https://зло.example", "", "cross-site"); code != http.StatusForbidden {
		t.Fatalf("запрос с чужого сайта: %d, ожидался 403", code)
	}
	if code := post(t, "", "", "cross-site"); code != http.StatusForbidden {
		t.Fatalf("cross-site без Origin: %d, ожидался 403", code)
	}
}

// Разделение по именам должно работать и за прокси: имя берётся из X-Forwarded-Host.
func TestHostSplitBehindProxy(t *testing.T) {
	e := newEnv(t)
	e.login(t)
	get := func(path, xfh string) int {
		req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
		req.Header.Set("X-Forwarded-Host", xfh)
		u, _ := url.Parse(e.srv.URL)
		for _, c := range e.client.Jar.Cookies(u) {
			req.AddCookie(c)
		}
		resp, _ := e.do(t, req)
		return resp.StatusCode
	}
	if code := get("/users", "panel.example.com"); code != http.StatusOK {
		t.Fatalf("админка на своём имени за прокси: %d", code)
	}
	if code := get("/users", "portal.example.com"); code != http.StatusNotFound {
		t.Fatalf("админка ответила на имени портала за прокси: %d", code)
	}
	if code := get("/users", "чужое.example"); code != http.StatusNotFound {
		t.Fatalf("админка ответила на чужом имени: %d", code)
	}
}

// Referrer-Policy: no-referrer заставляет браузер слать Origin: null даже своим же формам —
// на этом в панели отбивались все кнопки. «null» означает «источник не сообщён», а не «чужой».
func TestActionsWithNullOrigin(t *testing.T) {
	e := newEnv(t)
	csrf := e.login(t)

	send := func(origin, site string) int {
		form := url.Values{"csrf": {csrf}}
		req, _ := http.NewRequest("POST", e.srv.URL+"/logout", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		u, _ := url.Parse(e.srv.URL)
		for _, c := range e.client.Jar.Cookies(u) {
			req.AddCookie(c)
		}
		resp, _ := e.do(t, req)
		return resp.StatusCode
	}

	// Межсайтовый запрос браузер помечает сам — он отбивается даже с виду «пустым» источником.
	if code := send("null", "cross-site"); code != http.StatusForbidden {
		t.Fatalf("Origin: null с чужого сайта: %d, ожидался 403", code)
	}
	// А своя форма проходит — этот вызов заодно закрывает сессию, поэтому он последний.
	if code := send("null", "same-origin"); code != http.StatusSeeOther {
		t.Fatalf("Origin: null со своей страницы: %d, ожидался 303", code)
	}
	if resp, _ := e.get(t, "/"); resp.StatusCode != http.StatusSeeOther {
		t.Fatal("выход не закрыл сессию")
	}
}

// Страницы админки не должны просить браузер прятать источник: иначе он присылает Origin: null.
func TestAdminReferrerPolicy(t *testing.T) {
	e := newEnv(t)
	e.login(t)
	resp, _ := e.get(t, "/users")
	if got := resp.Header.Get("Referrer-Policy"); got != "same-origin" {
		t.Fatalf("Referrer-Policy админки: %q, ожидалось same-origin", got)
	}
}

// Корзина чистится по кнопке: обычно удалённое уходит само через 30 дней, но адрес в подсети
// всё это время занят, и иногда его нужно освободить сейчас.
func TestPurgeTrash(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	csrf := e.login(t)

	uid, _, err := e.store.CreateUser(ctx, store.User{Name: "Гости", MaxDevices: 5, DefaultInterfaceID: e.iface.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: uid, InterfaceID: e.iface.ID, Name: "Ноутбук"}); err != nil {
		t.Fatal(err)
	}
	e.action(t, "/users/"+itoa(uid)+"/delete", url.Values{}, csrf)

	// В корзине кнопка есть, в обычном списке — нет.
	_, trash := e.get(t, "/users?trash=1")
	if !strings.Contains(trash, `action="/users/purge"`) {
		t.Fatal("в корзине нет кнопки очистки")
	}
	if _, all := e.get(t, "/users"); strings.Contains(all, `action="/users/purge"`) {
		t.Fatal("кнопка очистки показана вне корзины")
	}

	e.action(t, "/users/purge", url.Values{}, csrf)
	if _, err := e.store.UserByName(ctx, "Гости"); err == nil {
		t.Fatal("пользователь остался в корзине после очистки")
	}
	entries, _ := e.store.Audit(ctx, store.AuditFilter{Action: "trash.purge"})
	if len(entries) != 1 {
		t.Fatalf("записей об очистке в журнале: %d", len(entries))
	}
}

// Умолчания интерфейса задаются из панели: DNS, keepalive и AllowedIPs пишутся одной формой и
// доходят до конфига в момент выдачи. До этого их знал только импортёр, и интерфейс, поднятый
// с нуля, оставался без DNS навсегда (FR-1.8).
func TestInterfaceDefaultsThroughUI(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	csrf := e.login(t)

	uid, _, err := e.store.CreateUser(ctx, store.User{Name: "Пётр", MaxDevices: 5, DefaultInterfaceID: e.iface.ID})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: uid, InterfaceID: e.iface.ID, Name: "Ноутбук"})
	if err != nil {
		t.Fatal(err)
	}
	devPath := "/devices/" + itoa(dev.ID) + "/conf"

	// Форма живёт на странице интерфейса — иначе задать умолчания по-прежнему негде. Адрес
	// страницы — идентификатор: одно имя живёт на разных машинах парка.
	iface0 := itoa(e.iface.ID)
	if _, page := e.get(t, "/interfaces/"+iface0); !strings.Contains(page, `action="/interfaces/`+iface0+`/defaults"`) {
		t.Fatal("на странице интерфейса нет формы умолчаний")
	}
	// Старая ссылка по имени продолжает открывать тот же интерфейс.
	if resp, _ := e.get(t, "/interfaces/awg-t0"); resp.StatusCode != 200 {
		t.Fatalf("страница по имени интерфейса: %d", resp.StatusCode)
	}

	// Сохранение: запятая без пробела приводится к общему виду.
	loc := e.action(t, "/interfaces/awg-t0/defaults", url.Values{
		"dns": {"10.40.0.1,1.1.1.1"}, "keepalive": {"25"}, "allowed_ips": {"0.0.0.0/0"},
	}, csrf)
	if msg, bad := flashOf(t, loc); bad != "" || !strings.Contains(msg, "умолчания сохранены") {
		t.Fatalf("сохранение умолчаний: ok=%q err=%q", msg, bad)
	}
	iface, err := e.hub.Interface(ctx, e.iface.ID)
	if err != nil {
		t.Fatal(err)
	}
	if iface.DefaultDNS != "10.40.0.1, 1.1.1.1" || iface.DefaultKeepalive != 25 || iface.DefaultAllowedIPs != "0.0.0.0/0" {
		t.Fatalf("умолчания не записались: %q %d %q", iface.DefaultDNS, iface.DefaultKeepalive, iface.DefaultAllowedIPs)
	}
	if entries, _ := e.store.Audit(ctx, store.AuditFilter{Action: "interface.defaults"}); len(entries) != 1 {
		t.Fatalf("записей об умолчаниях в журнале: %d", len(entries))
	}

	// Выданный конфиг собирается в момент выдачи и берёт новые умолчания.
	_, conf := e.get(t, devPath)
	for _, want := range []string{"DNS = 10.40.0.1, 1.1.1.1\n", "AllowedIPs = 0.0.0.0/0\n", "PersistentKeepalive = 25\n"} {
		if !strings.Contains(conf, want) {
			t.Fatalf("в конфиге нет %q:\n%s", want, conf)
		}
	}

	// Имя резолвера в строке DNS клиенты AmneziaWG не примут — форма отказывает сразу.
	loc = e.action(t, "/interfaces/awg-t0/defaults", url.Values{
		"dns": {"резолвер.дома"}, "keepalive": {"25"}, "allowed_ips": {"0.0.0.0/0"},
	}, csrf)
	if _, bad := flashOf(t, loc); !strings.Contains(bad, "не IP-адрес") {
		t.Fatalf("кривой DNS принят: err=%q", bad)
	}

	// Пустой AllowedIPs оставил бы конфиг без маршрутов.
	loc = e.action(t, "/interfaces/awg-t0/defaults", url.Values{
		"dns": {"10.40.0.1"}, "keepalive": {"25"}, "allowed_ips": {"  "},
	}, csrf)
	if _, bad := flashOf(t, loc); !strings.Contains(bad, "AllowedIPs") {
		t.Fatalf("пустой AllowedIPs принят: err=%q", bad)
	}
	// Оба отказа ничего не сохранили.
	if iface, _ = e.hub.Interface(ctx, e.iface.ID); iface.DefaultDNS != "10.40.0.1, 1.1.1.1" {
		t.Fatalf("после отказа умолчания изменились: %q", iface.DefaultDNS)
	}

	// Пустой DNS — законное значение: строки DNS в конфиге не будет вовсе.
	e.action(t, "/interfaces/awg-t0/defaults", url.Values{
		"dns": {""}, "keepalive": {"0"}, "allowed_ips": {"0.0.0.0/0, ::/0"},
	}, csrf)
	_, conf = e.get(t, devPath)
	if strings.Contains(conf, "DNS") {
		t.Fatalf("строка DNS осталась при пустом умолчании:\n%s", conf)
	}
	if strings.Contains(conf, "PersistentKeepalive") {
		t.Fatalf("keepalive 0 всё равно попал в конфиг:\n%s", conf)
	}
	if !strings.Contains(conf, "AllowedIPs = 0.0.0.0/0, ::/0\n") {
		t.Fatalf("список AllowedIPs не дошёл до конфига:\n%s", conf)
	}

	// Переопределение устройства сильнее умолчания и сменой умолчаний не переписывается.
	fresh, err := e.store.DeviceByID(ctx, dev.ID)
	if err != nil {
		t.Fatal(err)
	}
	fresh.Overrides.DNS = "9.9.9.9"
	if err := e.hub.UpdateDevice(ctx, fresh, store.ActorAdmin, ""); err != nil {
		t.Fatal(err)
	}
	e.action(t, "/interfaces/awg-t0/defaults", url.Values{
		"dns": {"10.40.0.1"}, "keepalive": {"0"}, "allowed_ips": {"0.0.0.0/0"},
	}, csrf)
	if _, conf = e.get(t, devPath); !strings.Contains(conf, "DNS = 9.9.9.9\n") {
		t.Fatalf("переопределение устройства потеряно:\n%s", conf)
	}
}

// Ничьи пиры собраны в одном месте: раньше их приходилось искать внутри каждого интерфейса,
// а на четырёх серверах это дюжина экранов. Строка в списке людей ведёт на общий разбор (FR-1.6).
func TestOrphanPeersHaveTheirOwnPlace(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	csrf := e.login(t)
	now := time.Now()

	uid, _, err := e.store.CreateUser(ctx, store.User{Name: "Хозяин", MaxDevices: 5, DefaultInterfaceID: e.iface.ID})
	if err != nil {
		t.Fatal(err)
	}
	// Пока ничьих нет, строки в списке тоже нет.
	if _, body := e.get(t, "/users"); strings.Contains(body, "Пиры-сироты") {
		t.Fatal("строка сирот показана, когда сирот нет")
	}
	for i, key := range []string{"ORPHAN1=", "ORPHAN2=", "ORPHAN3="} {
		if _, err := e.store.DB().ExecContext(ctx, `INSERT INTO peers (interface_id, public_key, allowed_ips, in_conf, first_seen_at, last_seen_at)
			VALUES (?, ?, ?, 1, ?, ?)`, e.iface.ID, key, "10.20.0."+itoa(int64(70+i))+"/32", now.Add(-time.Hour).Unix(), now.Unix()); err != nil {
			t.Fatal(err)
		}
	}

	_, body := e.get(t, "/users")
	if !strings.Contains(body, "Пиры-сироты") || !strings.Contains(body, "3 пира") {
		t.Fatal("в списке людей нет строки о ничьих пирах со счётчиком")
	}
	resp, page := e.get(t, "/users/orphans")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("страница сирот: %d", resp.StatusCode)
	}
	for _, want := range []string{"10.20.0.70/32", "10.20.0.71/32", "10.20.0.72/32", "Хозяин", "awg-t0"} {
		if !strings.Contains(page, want) {
			t.Fatalf("на странице сирот нет %q", want)
		}
	}

	// Привязка возвращает на ту же страницу, а привязанный пир уходит из списка.
	loc := e.action(t, "/interfaces/"+itoa(e.iface.ID)+"/adopt", url.Values{
		"public_key": {"ORPHAN2="}, "user_id": {itoa(uid)}, "name": {"Чужой роутер"}, "back": {"/users/orphans"},
	}, csrf)
	if !strings.HasPrefix(loc, "/users/orphans") {
		t.Fatalf("после привязки ушли на %q", loc)
	}
	if msg, bad := flashOf(t, loc); bad != "" || !strings.Contains(msg, "привязан") {
		t.Fatalf("привязка: ok=%q err=%q", msg, bad)
	}
	_, page = e.get(t, "/users/orphans")
	if strings.Contains(page, "10.20.0.71/32") {
		t.Fatal("привязанный пир остался среди сирот")
	}
	devices, _ := e.store.DevicesByUser(ctx, uid)
	if len(devices) != 1 || devices[0].Name != "Чужой роутер" {
		t.Fatalf("устройство из пира: %+v", devices)
	}
}
