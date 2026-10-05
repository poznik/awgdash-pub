package web

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/poznik/awgdash-pub/internal/auth"
	"github.com/poznik/awgdash-pub/internal/awgtest"
	"github.com/poznik/awgdash-pub/internal/config"
	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/node"
	"github.com/poznik/awgdash-pub/internal/store"
)

const testPassword = "пароль-для-теста"

type testEnv struct {
	srv    *httptest.Server
	web    *Server
	client *http.Client
	store  *store.Store
	hub    *hub.Hub
	admin  store.Admin
	iface  store.Interface
}

func newEnv(t *testing.T) *testEnv {
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

	n := node.New(confDir, "awg", awgtest.New(), []string{"wg-dashboard.service"})
	n.BackupDir = filepath.Join(dir, "conf-backup")
	// DataDir — свой у каждой среды. С пустым значением каталог копий превращался в «backups»
	// рядом с тестами: один тест клал туда файл, другой судил по его возрасту о делах на обзоре,
	// и исход зависел от того, когда пакет гоняли в прошлый раз.
	cfg := &config.Config{ServerSlug: "de", ServerTitle: "Германия", AdminHost: "panel.example.com", TZ: "UTC", DBPath: "тест.db", DataDir: dir}
	h := hub.New(cfg, st, n, slog.New(slog.NewTextHandler(io.Discard, nil)))
	srvID, err := st.UpsertLocalServer(ctx, "de", "Германия")
	if err != nil {
		t.Fatal(err)
	}
	h.ServerID = srvID
	if _, err := st.UpsertInterface(ctx, srvID, "awg-t0", store.InterfaceFacts{
		Subnet: "10.20.0.0/16", ServerAddress: "10.20.0.1/16", ListenPort: 443, MTU: 1280, IsAWG: true,
		ServerPublicKey: awgtest.ServerPublicKey, Obfuscation: map[string]string{"Jc": "6", "I1": "<b 0x01>"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.DB().ExecContext(ctx, `UPDATE interfaces SET endpoints = ? WHERE name = 'awg-t0'`,
		`[{"label":"основной","host":"vpn.example.com","port":443,"primary":true},{"label":"запасной порт","host":"vpn.example.com","port":8443}]`); err != nil {
		t.Fatal(err)
	}
	// Интерфейс среды — под управлением панели, как на живом парке: формы создания устройства
	// наблюдаемые не предлагают вовсе (FR-3.1), и на observe половина сценариев была бы мертва.
	first, _ := st.Interfaces(ctx, srvID)
	if err := st.SetInterfaceMode(ctx, first[0].ID, hub.ModeOwn); err != nil {
		t.Fatal(err)
	}
	ifaces, _ := st.Interfaces(ctx, srvID)

	hash, err := auth.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	adminID, err := st.CreateAdmin(ctx, "admin", hash)
	if err != nil {
		t.Fatal(err)
	}
	admin, _ := st.AdminByID(ctx, adminID)

	// ForwardedHops: 1 — как в проде: панель стоит за одним обратным прокси.
	s, err := New(h, time.UTC, Options{AdminHost: "panel.example.com", PortalHost: "portal.example.com",
		SessionKey: []byte("тестовый-ключ-подписи"), ForwardedHops: 1})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.Register(mux)
	ts := httptest.NewUnstartedServer(mux)
	// Стенд для осмотра UI удобнее держать на постоянном порту: адрес не меняется между
	// перезапусками. В обычном прогоне переменная не задана и порт по-прежнему случайный.
	if port := os.Getenv("AWGDASH_STAND_PORT"); port != "" {
		l, err := net.Listen("tcp", "127.0.0.1:"+port)
		if err != nil {
			t.Fatalf("порт стенда %s занят: %v", port, err)
		}
		ts.Listener.Close()
		ts.Listener = l
	}
	ts.Start()
	t.Cleanup(ts.Close)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &testEnv{srv: ts, web: s, client: client, store: st, hub: h, admin: admin, iface: ifaces[0]}
}

// putBackup кладёт в каталог копий файл с заданным временем изменения. Настоящая копия страницам
// не нужна: настройки показывают имя и размер, а очередь дел судит о свежести по времени файла.
func (e *testEnv) putBackup(t *testing.T, at time.Time) {
	t.Helper()
	dir := e.hub.BackupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "awgdash-config-20260825-0330.tar.zst.age")
	if err := os.WriteFile(path, []byte("не настоящая копия, важен только размер"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, at, at); err != nil {
		t.Fatal(err)
	}
}

func (e *testEnv) get(t *testing.T, path string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	return e.do(t, req)
}

func (e *testEnv) post(t *testing.T, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", e.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return e.do(t, req)
}

// withHost подменяет имя виртуального хоста. Куки приходится прикладывать руками: при
// req.Host, отличном от адреса в URL, клиент Go их из jar не берёт (браузер шлёт их по домену).
func (e *testEnv) withHost(t *testing.T, host, path string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	req.Host = host
	u, _ := url.Parse(e.srv.URL)
	for _, c := range e.client.Jar.Cookies(u) {
		req.AddCookie(c)
	}
	return e.do(t, req)
}

func (e *testEnv) do(t *testing.T, req *http.Request) (*http.Response, string) {
	t.Helper()
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// login проходит вход паролем и возвращает CSRF-токен со страницы.
func (e *testEnv) login(t *testing.T) string {
	t.Helper()
	resp, body := e.post(t, "/login", url.Values{"username": {"admin"}, "password": {testPassword}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("вход: %d %s", resp.StatusCode, body)
	}
	_, page := e.get(t, "/")
	return csrfOf(page)
}

func csrfOf(page string) string {
	const marker = `name="csrf" value="`
	i := strings.Index(page, marker)
	if i < 0 {
		return ""
	}
	rest := page[i+len(marker):]
	if j := strings.IndexByte(rest, '"'); j > 0 {
		return rest[:j]
	}
	return ""
}

func TestLoginRequired(t *testing.T) {
	e := newEnv(t)
	for _, path := range []string{"/", "/users", "/interfaces", "/events", "/settings"} {
		resp, _ := e.get(t, path)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("%s без входа: %d", path, resp.StatusCode)
		}
		if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "/login") {
			t.Fatalf("%s ведёт не на вход: %s", path, loc)
		}
	}
	resp, body := e.get(t, "/login")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Пароль") {
		t.Fatalf("страница входа: %d", resp.StatusCode)
	}
}

func TestLoginWrongPassword(t *testing.T) {
	e := newEnv(t)
	resp, body := e.post(t, "/login", url.Values{"username": {"admin"}, "password": {"чужой-пароль-123"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("неверный пароль: %d", resp.StatusCode)
	}
	if !strings.Contains(body, "неверный логин или пароль") {
		t.Fatalf("нет сообщения об ошибке: %s", body)
	}
	// Неизвестное имя отвечает тем же текстом: перечислить администраторов нельзя.
	_, body = e.post(t, "/login", url.Values{"username": {"нет-такого"}, "password": {testPassword}})
	if !strings.Contains(body, "неверный логин или пароль") {
		t.Fatal("ответ для несуществующего имени отличается")
	}
	entries, _ := e.store.Audit(context.Background(), store.AuditFilter{Action: "admin.login_failed"})
	if len(entries) != 2 {
		t.Fatalf("неудачные входы в журнале: %d", len(entries))
	}
}

func TestLoginAndPages(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	userID, _, err := e.store.CreateUser(ctx, store.User{Name: "Анна", DefaultInterfaceID: e.iface.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: userID, InterfaceID: e.iface.ID, Name: "Телефон"}); err != nil {
		t.Fatal(err)
	}

	e.login(t)
	pages := map[string]string{
		"/":                      "Обзор",
		"/users":                 "Анна",
		"/users/" + itoa(userID): "Телефон",
		"/interfaces":            "awg-t0",
		"/interfaces/awg-t0":     "обфускация",
		"/events":                "Журнал",
		"/settings":              "Второй фактор",
	}
	for path, want := range pages {
		resp, body := e.get(t, path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		if !strings.Contains(body, want) {
			t.Fatalf("%s: нет %q на странице", path, want)
		}
		for _, secret := range []string{"PrivateKey", "$argon2id", "awgdash_session="} {
			if strings.Contains(body, secret) {
				t.Fatalf("%s: на страницу попало %q", path, secret)
			}
		}
	}
	// Ссылка пользователя показывается с именем портала.
	_, body := e.get(t, "/users/"+itoa(userID))
	if !strings.Contains(body, "https://portal.example.com/u/") {
		t.Fatal("нет персональной ссылки")
	}
}

func TestDeviceConfigAndFile(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	userID, _, _ := e.store.CreateUser(ctx, store.User{Name: "Анна", DefaultInterfaceID: e.iface.ID})
	dev, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: userID, InterfaceID: e.iface.ID, Name: "Телефон"})
	if err != nil {
		t.Fatal(err)
	}
	e.login(t)

	resp, body := e.get(t, "/devices/"+itoa(dev.ID)+"/config")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("страница конфига: %d", resp.StatusCode)
	}
	for _, want := range []string{"<svg", "Endpoint = vpn.example.com:443", "Скачать .conf", "запасной порт"} {
		if !strings.Contains(body, want) {
			t.Fatalf("нет %q на странице конфига", want)
		}
	}
	// Вариант endpoint меняет ровно строку Endpoint.
	_, alt := e.get(t, "/devices/"+itoa(dev.ID)+"/config?ep="+url.QueryEscape("запасной порт"))
	if !strings.Contains(alt, "Endpoint = vpn.example.com:8443") {
		t.Fatal("запасной порт не применился")
	}

	resp, file := e.get(t, "/devices/"+itoa(dev.ID)+"/conf")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("скачивание: %d", resp.StatusCode)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("Content-Disposition: %s", cd)
	}
	if !strings.HasPrefix(file, "[Interface]") || !strings.Contains(file, "PrivateKey = ") {
		t.Fatalf("файл конфига: %.60s", file)
	}
	entries, _ := e.store.Audit(ctx, store.AuditFilter{Action: "device.config_issued"})
	if len(entries) != 3 {
		t.Fatalf("выдач в журнале: %d (ожидалось 3)", len(entries))
	}
}

func TestCSRFAndLogout(t *testing.T) {
	e := newEnv(t)
	csrf := e.login(t)
	if csrf == "" {
		t.Fatal("на странице нет CSRF-токена")
	}
	resp, _ := e.post(t, "/logout", url.Values{})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("выход без токена: %d", resp.StatusCode)
	}
	resp, _ = e.post(t, "/logout", url.Values{"csrf": {"чужой"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("выход с чужим токеном: %d", resp.StatusCode)
	}
	resp, _ = e.post(t, "/logout", url.Values{"csrf": {csrf}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("выход: %d", resp.StatusCode)
	}
	resp, _ = e.get(t, "/")
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatal("сессия пережила выход")
	}
}

func TestTOTPFlow(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	secret, _, err := auth.NewTOTP("awgdash", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.store.SetTOTP(ctx, e.admin.ID, secret, true); err != nil {
		t.Fatal(err)
	}

	resp, body := e.post(t, "/login", url.Values{"username": {"admin"}, "password": {testPassword}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Код") {
		t.Fatalf("после пароля не спросили код: %d %s", resp.StatusCode, body)
	}
	// Пароль пройден, но сессии ещё нет.
	if r, _ := e.get(t, "/"); r.StatusCode != http.StatusSeeOther {
		t.Fatal("сессия выдана до второго фактора")
	}
	resp, _ = e.post(t, "/login/totp", url.Values{"code": {"000000"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("неверный код: %d", resp.StatusCode)
	}
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	resp, _ = e.post(t, "/login/totp", url.Values{"code": {code}})
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("верный код: %d", resp.StatusCode)
	}
	if r, _ := e.get(t, "/"); r.StatusCode != http.StatusOK {
		t.Fatal("после второго фактора сессии нет")
	}
}

func TestHostSplitAndHealthz(t *testing.T) {
	e := newEnv(t)
	e.login(t)
	// Запрос с чужим именем (портал) до админки не доходит.
	resp, _ := e.withHost(t, "portal.example.com", "/users")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("админка ответила на имени портала: %d", resp.StatusCode)
	}
	if resp, _ := e.withHost(t, "panel.example.com", "/users"); resp.StatusCode != http.StatusOK {
		t.Fatalf("админка не ответила на своём имени: %d", resp.StatusCode)
	}
	// Вход тоже спрятан за именем.
	if resp, _ := e.withHost(t, "portal.example.com", "/login"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("страница входа открылась на имени портала: %d", resp.StatusCode)
	}

	// healthz открыт, но наружу не показывает текст ошибки.
	resp, body := e.withHost(t, "panel.example.com", "/healthz")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("healthz: %d %s", resp.StatusCode, body)
	}
	if strings.Contains(body, "last_error") {
		t.Fatalf("healthz наружу отдал текст ошибки: %s", body)
	}
}

func TestStaticAssets(t *testing.T) {
	e := newEnv(t)
	e.login(t)
	_, page := e.get(t, "/")
	// Имя файла стилей содержит хэш — иначе браузер покажет старую версию после обновления.
	i := strings.Index(page, "/static/app.")
	if i < 0 {
		t.Fatal("на странице нет ссылки на app.css")
	}
	href := page[i:]
	href = href[:strings.IndexByte(href, '"')]
	if !strings.HasSuffix(href, ".css") || len(href) < len("/static/app.0123456789.css") {
		t.Fatalf("имя файла без хэша: %s", href)
	}
	resp, body := e.get(t, href)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, ".card") {
		t.Fatalf("статика: %d", resp.StatusCode)
	}
	if cc := resp.Header.Get("Cache-Control"); !strings.Contains(cc, "immutable") {
		t.Fatalf("Cache-Control статики: %s", cc)
	}
}

func TestLivePartials(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	userID, _, _ := e.store.CreateUser(ctx, store.User{Name: "Анна", DefaultInterfaceID: e.iface.ID})
	if _, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: userID, InterfaceID: e.iface.ID, Name: "Телефон"}); err != nil {
		t.Fatal(err)
	}
	e.login(t)

	cases := map[string]string{
		"/live/dashboard":             "Кто грузит канал сейчас",
		"/live/users":                 "Анна",
		"/live/users/" + itoa(userID): "Последняя активность",
		"/live/interfaces/awg-t0":     "В туннеле",
	}
	for path, want := range cases {
		resp, body := e.get(t, path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		if !strings.Contains(body, want) {
			t.Fatalf("%s: нет %q во фрагменте", path, want)
		}
		// Фрагмент — кусок страницы: ни каркаса, ни повторной загрузки стилей.
		for _, bad := range []string{"<!doctype", "<html", "<body", "<script"} {
			if strings.Contains(strings.ToLower(body), bad) {
				t.Fatalf("%s: во фрагменте оказался %q", path, bad)
			}
		}
		// Бюджет ТЗ §7.1: ответ живого запроса ≤ 5 КБ.
		if len(body) > 5*1024 {
			t.Fatalf("%s: фрагмент %d байт, бюджет 5 КБ", path, len(body))
		}
		if resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: фрагмент кэшируется (%s)", path, resp.Header.Get("Cache-Control"))
		}
	}
	// Страница ссылается на живые блоки и на скрипт, который их обновляет.
	_, page := e.get(t, "/")
	if !strings.Contains(page, `data-live="/live/dashboard"`) || !strings.Contains(page, "/static/live.") {
		t.Fatal("на странице нет живого блока или скрипта")
	}
	// Без входа фрагменты не отдаются.
	e.client.Jar, _ = cookiejar.New(nil)
	if resp, _ := e.get(t, "/live/dashboard"); resp.StatusCode == http.StatusOK {
		t.Fatal("живой фрагмент отдан без входа")
	}
}

func TestPageBudget(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// 200 пользователей × 3 устройства — нагрузка из ТЗ §7.1.
	for i := 0; i < 200; i++ {
		id, _, err := e.store.CreateUser(ctx, store.User{Name: "Пользователь " + itoa(int64(i)), DefaultInterfaceID: e.iface.ID, MaxDevices: 5})
		if err != nil {
			t.Fatal(err)
		}
		for j := 0; j < 3; j++ {
			if _, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: id, InterfaceID: e.iface.ID, Name: "Устройство " + itoa(int64(j))}); err != nil {
				t.Fatal(err)
			}
		}
	}
	e.login(t)

	// Вес страницы (HTML) — бюджет 60 КБ; статика и шрифты кэшируются и в бюджет не входят.
	for _, path := range []string{"/", "/users", "/users/1", "/interfaces/awg-t0", "/events", "/settings", "/server", "/devices/1"} {
		start := time.Now()
		resp, body := e.get(t, path)
		took := time.Since(start)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		if len(body) > 60*1024 {
			t.Fatalf("%s: %d байт, бюджет 60 КБ", path, len(body))
		}
		t.Logf("%-22s %5.1f КБ  %v", path, float64(len(body))/1024, took.Round(time.Millisecond))
	}
	// Список отдаёт страницу по 60 пользователей, а не всех разом.
	_, page := e.get(t, "/users")
	if strings.Count(page, `class="item"`) > usersPerPage+2 {
		t.Fatalf("на странице %d элементов списка — пагинация не работает", strings.Count(page, `class="item"`))
	}
}

// ZgotmplZ — след того, что html/template отверг значение в контексте страницы: так пропали
// стили портала. Проверяем разом все страницы, чтобы не искать это снова глазами.
func TestNoDroppedTemplateValues(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	userID, _, _ := e.store.CreateUser(ctx, store.User{Name: "Анна", DefaultInterfaceID: e.iface.ID, SelfService: true})
	dev, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: userID, InterfaceID: e.iface.ID, Name: "Телефон"})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := e.store.UserByID(ctx, userID)
	e.login(t)

	pages := []string{"/", "/users", "/users/" + itoa(userID), "/devices/" + itoa(dev.ID) + "/config",
		"/interfaces/awg-t0", "/events", "/settings", "/login"}
	for _, path := range pages {
		_, body := e.get(t, path)
		if strings.Contains(body, "ZgotmplZ") {
			t.Fatalf("%s: шаблон выкинул значение (ZgotmplZ)", path)
		}
	}
	for _, path := range []string{"/u/" + u.Token, "/u/" + u.Token + "/devices/" + itoa(dev.ID)} {
		_, body := e.portalGet(t, path)
		if strings.Contains(body, "ZgotmplZ") {
			t.Fatalf("%s: шаблон выкинул значение (ZgotmplZ)", path)
		}
	}
}

// Кнопка «скопировать» рядом со ссылкой и конфигом: JS в панели допускается ровно для этого,
// но разметка должна быть на месте и указывать на существующий элемент.
func TestCopyButtons(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	userID, _, _ := e.store.CreateUser(ctx, store.User{Name: "Анна", DefaultInterfaceID: e.iface.ID})
	dev, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: userID, InterfaceID: e.iface.ID, Name: "Телефон"})
	if err != nil {
		t.Fatal(err)
	}
	e.login(t)

	_, page := e.get(t, "/users/"+itoa(userID))
	for _, want := range []string{`id="portal-link"`, `data-copy="#portal-link"`, "Скопировать", `data-toast`} {
		if !strings.Contains(page, want) {
			t.Fatalf("на карточке пользователя нет %q", want)
		}
	}
	_, cfg := e.get(t, "/devices/"+itoa(dev.ID)+"/config")
	for _, want := range []string{`id="conf-text"`, `data-copy="#conf-text"`} {
		if !strings.Contains(cfg, want) {
			t.Fatalf("на странице конфига нет %q", want)
		}
	}
	// Скрипт копирования приезжает тем же файлом, что и живые данные — лишних запросов нет.
	i := strings.Index(page, "/static/live.")
	if i < 0 {
		t.Fatal("на странице нет скрипта")
	}
	href := page[i:]
	href = href[:strings.IndexByte(href, '"')]
	_, js := e.get(t, href)
	if !strings.Contains(js, "data-copy") || !strings.Contains(js, "data-toast") {
		t.Fatal("в скрипте нет обработчика копирования")
	}
}

// Страницы статистики: итоги, графики, окна, таблица по дням (SPEC §6.6, §7.2).
func TestStatsPages(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	userID, _, _ := e.store.CreateUser(ctx, store.User{Name: "Анна", DefaultInterfaceID: e.iface.ID})
	dev, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: userID, InterfaceID: e.iface.ID, Name: "Телефон"})
	if err != nil {
		t.Fatal(err)
	}
	// Немного истории: два сэмпла дают дельту, метрики хоста — «панель работала».
	now := time.Now()
	base := store.PeerSample{PublicKey: dev.PublicKey, AllowedIPs: dev.Address + "/32", LastHandshake: now.Add(-time.Minute)}
	if _, err := e.store.ApplySample(ctx, e.iface.ID, now.Add(-30*time.Second), []store.PeerSample{base}, store.OnlineWindow); err != nil {
		t.Fatal(err)
	}
	next := base
	next.Rx, next.Tx = 5_000_000, 1_000_000
	if _, err := e.store.ApplySample(ctx, e.iface.ID, now, []store.PeerSample{next}, store.OnlineWindow); err != nil {
		t.Fatal(err)
	}
	if err := e.store.InsertHostMetric(ctx, store.HostMetric{ServerID: e.hub.ServerID, TS: now, CPU: 3,
		MemUsed: 700 << 20, MemTotal: 8 << 30, DiskUsed: 6 << 30, DiskTotal: 78 << 30, Load1: 0.2, NetRxBps: 1000}); err != nil {
		t.Fatal(err)
	}
	e.login(t)

	// Карточка устройства: состояние, итоги, график, дни.
	resp, body := e.get(t, "/devices/"+itoa(dev.ID))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("страница устройства: %d", resp.StatusCode)
	}
	for _, want := range []string{"Итоги", "За всё время", "Трафик", "24 часа", "<polyline", "Последний хендшейк"} {
		if !strings.Contains(body, want) {
			t.Fatalf("на странице устройства нет %q", want)
		}
	}
	if !strings.Contains(body, "5.0 МБ") {
		t.Fatalf("итоги не показывают дельту 5 МБ")
	}
	// Окна графика переключаются ссылками и без JS.
	for _, rng := range []string{"week", "month"} {
		resp, body := e.get(t, "/devices/"+itoa(dev.ID)+"?range="+rng)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("окно %s: %d", rng, resp.StatusCode)
		}
		if !strings.Contains(body, `aria-current="page"`) {
			t.Fatalf("окно %s не отмечено выбранным", rng)
		}
	}

	// Карточка пользователя и интерфейса тоже показывают итоги и график.
	_, page := e.get(t, "/users/"+itoa(userID))
	for _, want := range []string{"Итоги", "Трафик", "<polyline"} {
		if !strings.Contains(page, want) {
			t.Fatalf("на карточке пользователя нет %q", want)
		}
	}
	_, iface := e.get(t, "/interfaces/awg-t0")
	for _, want := range []string{"Сейчас", "Пиры", "За всё время", "Трафик"} {
		if !strings.Contains(iface, want) {
			t.Fatalf("на странице интерфейса нет %q", want)
		}
	}

	// Страница сервера: метрики, пороги, размер базы.
	resp, srv := e.get(t, "/server")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("страница сервера: %d — %.200s", resp.StatusCode, srv)
	}
	for _, want := range []string{"Процессор за сутки", "Память и своп", "Сеть за сутки", "Пороги", "База панели"} {
		if !strings.Contains(srv, want) {
			t.Fatalf("на странице сервера нет %q", want)
		}
	}
}

// На телефоне раскладка показывает одну панель из двух: список или деталь (app.css, data-pane).
// Пока флаг выставлялся единственным обработчиком, с телефона нельзя было открыть ни человека,
// ни QR, ни настройки — оставались только списки.
func TestPhoneShowsWholePage(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	userID, _, err := e.store.CreateUser(ctx, store.User{Name: "Анна", DefaultInterfaceID: e.iface.ID})
	if err != nil {
		t.Fatal(err)
	}
	dev, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: userID, InterfaceID: e.iface.ID, Name: "Телефон"})
	if err != nil {
		t.Fatal(err)
	}
	e.login(t)

	// Вся админка живёт одной колонкой: делить нечего, а вниз ведут табы. Прежняя раскладка
	// «список · деталь» прятала на телефоне правую панель — из-за этого с телефона нельзя было
	// открыть ни человека, ни QR.
	for _, path := range []string{
		"/",
		"/users",
		"/users/" + itoa(userID),
		"/devices/" + itoa(dev.ID),
		"/devices/" + itoa(dev.ID) + "/config",
		"/users/" + itoa(userID) + "/devices/new",
		"/interfaces",
		"/interfaces/awg-t0",
		"/server",
		"/events",
		"/settings",
	} {
		resp, body := e.get(t, path)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		if strings.Contains(body, "data-pane") {
			t.Fatalf("%s: страница всё ещё делится на список и деталь", path)
		}
		if !strings.Contains(body, `class="tabs"`) {
			t.Fatalf("%s: нет нижних табов — с телефона не перейти в другой раздел", path)
		}
	}

}

// Страница настроек с живыми копиями: размер файла приходит int64, а счётчики трафика uint64.
// На несовпадении типов шаблон падал, и настройки не открывались вовсе — это увидели
// сразу после выкатки.
func TestSettingsWithBackups(t *testing.T) {
	e := newEnv(t)
	e.putBackup(t, time.Now())
	e.login(t)
	resp, body := e.get(t, "/settings")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("настройки: %d — %.200s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "awgdash-config-20260825-0330") {
		t.Fatal("копия не показана в настройках")
	}
	if strings.Contains(body, "wrong type") || strings.Contains(body, "шаблон settings") {
		t.Fatalf("шаблон упал: %.300s", body)
	}
}

// Имя панели задаётся администратором и живёт в настройках: вкладка браузера, левый верхний угол
// и страница входа. Панелей может быть несколько, и они должны отличаться с первого взгляда.
func TestBrandIsSettableAndSticks(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	// По умолчанию — awgdash.
	_, page := e.get(t, "/login")
	if !strings.Contains(page, "awgdash") {
		t.Fatal("на входе нет имени по умолчанию")
	}
	csrf := e.login(t)

	if resp, body := e.post(t, "/settings/brand", url.Values{"csrf": {csrf}, "brand": {"Домашний VPN"}}); resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("сохранение имени: %d %s", resp.StatusCode, body)
	}
	_, dash := e.get(t, "/")
	if !strings.Contains(dash, "<title>Обзор · Домашний VPN</title>") {
		t.Fatal("имя не попало во вкладку браузера")
	}
	if !strings.Contains(dash, `class="top__brand" href="/">Домашний VPN`) {
		t.Fatal("имя не попало в левый верхний угол")
	}

	// Хранится в настройках, а не в памяти процесса: переживает перезапуск.
	if got, _ := e.store.Brand(ctx); got != "Домашний VPN" {
		t.Fatalf("в настройках лежит %q", got)
	}

	// Пустое значение возвращает имя по умолчанию.
	e.post(t, "/settings/brand", url.Values{"csrf": {csrf}, "brand": {"  "}})
	_, dash = e.get(t, "/")
	if !strings.Contains(dash, "<title>Обзор · awgdash</title>") {
		t.Fatal("пустое имя не вернуло awgdash")
	}

	// Слишком длинное имя отклоняется с объяснением.
	long := strings.Repeat("я", 40)
	resp, _ := e.post(t, "/settings/brand", url.Values{"csrf": {csrf}, "brand": {long}})
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "err=") {
		t.Fatalf("длинное имя не отклонено: %s", loc)
	}
	if got, _ := e.store.Brand(ctx); got != store.DefaultBrand {
		t.Fatalf("длинное имя сохранилось: %q", got)
	}
}
