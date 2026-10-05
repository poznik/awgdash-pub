// Package web — админка панели (SPEC §8, design.md, направление C «Раздельный вид»):
// рельса разделов · список · деталь. Портал пользователей — M4.
package web

import (
	"bytes"
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/fs"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/store"
	"github.com/poznik/awgdash-pub/internal/version"
)

//go:embed templates/*.html
var templates embed.FS

//go:embed static
var static embed.FS

// Options — то, что сервер знает о своём окружении.
type Options struct {
	AdminHost  string // единственное внешнее имя админки; пусто — проверка Host не делается
	PortalHost string // имя портала (M4): на нём админские маршруты не отвечают
	SessionKey []byte // ключ для подписи промежуточной куки второго фактора
	// ForwardedHops — сколько обратных прокси стоит перед панелью (FR-13.1b). Ноль означает
	// «X-Forwarded-For не разбирать»: тогда адресом клиента считается RemoteAddr.
	ForwardedHops int
}

// Server — HTTP-обработчики хаба.
type Server struct {
	Hub           *hub.Hub
	TZ            *time.Location
	AdminHost     string
	PortalHost    string
	SessionKey    []byte
	ForwardedHops int
	Login         *limiter
	Portal        *limiter
	// pwSlots — сколько проверок пароля идёт одновременно. argon2id держит 64 МиБ на проверку,
	// а юнит живёт в 192 МБ: десяток параллельных попыток входа означал бы OOM (FR-13.1d).
	pwSlots chan struct{}
	// WA — незаконченные попытки входа и регистрации ключей (WebAuthn).
	WA *waSessions

	tpl    *template.Template
	assets map[string]asset // путь → содержимое с хэшем в имени

	// brand — имя панели из настроек; читается на каждой странице, пишется редко.
	brandMu sync.RWMutex
	brand   string
}

type asset struct {
	name  string // static/app.<хэш>.css
	body  []byte
	ctype string
}

// New собирает сервер: шаблоны, статика с хэшем в имени, ограничитель попыток входа.
func New(h *hub.Hub, tz *time.Location, opt Options) (*Server, error) {
	s := &Server{Hub: h, TZ: tz, AdminHost: opt.AdminHost, PortalHost: opt.PortalHost, SessionKey: opt.SessionKey,
		ForwardedHops: opt.ForwardedHops,
		Login:         newLimiter(5, 5*time.Minute), Portal: newLimiter(portalRateLimit, time.Minute),
		pwSlots: make(chan struct{}, maxPasswordChecks),
		WA:      newWASessions(), assets: map[string]asset{}}
	t, err := template.New("").Funcs(s.funcs()).ParseFS(templates, "templates/*.html")
	if err != nil {
		return nil, err
	}
	s.tpl = t
	if err := s.loadAssets(); err != nil {
		return nil, err
	}
	// Ключи, заведённые до появления колонки с именем панели, привязываем к имени админки:
	// иначе кнопка входа по ключу показывалась бы и там, где ключ не сработает.
	if brand, err := h.Store.Brand(context.Background()); err == nil {
		s.brand = brand
	}
	if opt.AdminHost != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if n, err := h.Store.FillPasskeyRPID(ctx, hostOnly(opt.AdminHost)); err == nil && n > 0 {
			h.Log.Info("ключам входа проставлено имя панели", "n", n, "host", opt.AdminHost)
		}
	}
	return s, nil
}

// loadAssets читает статику и даёт каждому файлу имя с хэшем: содержимое кэшируется навсегда,
// а новая версия панели приезжает под новым именем.
func (s *Server) loadAssets() error {
	return fs.WalkDir(static, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		body, err := static.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		short := base64.RawURLEncoding.EncodeToString(sum[:])[:10]
		base := strings.TrimPrefix(path, "static/")
		dir := ""
		if i := strings.LastIndexByte(base, '/'); i >= 0 {
			dir, base = base[:i+1], base[i+1:]
		}
		ext := ""
		if i := strings.LastIndexByte(base, '.'); i >= 0 {
			ext, base = base[i:], base[:i]
		}
		ctype := "text/plain; charset=utf-8"
		switch ext {
		case ".css":
			ctype = "text/css; charset=utf-8"
		case ".js":
			ctype = "text/javascript; charset=utf-8"
		case ".svg":
			ctype = "image/svg+xml"
		case ".woff2":
			ctype = "font/woff2"
		}
		// Шрифты остаются под своими именами: на них ссылается fonts.css, который сам приезжает с хэшем.
		if dir != "" {
			s.assets[dir+base+ext] = asset{name: "/static/" + dir + base + ext, body: body, ctype: ctype}
			return nil
		}
		s.assets[base+ext] = asset{name: "/static/" + base + "." + short + ext, body: body, ctype: ctype}
		return nil
	})
}

// Brand — имя панели. Держится в памяти: его читает каждая страница, а меняется оно раз в жизни.
func (s *Server) Brand() string {
	s.brandMu.RLock()
	defer s.brandMu.RUnlock()
	if s.brand == "" {
		return store.DefaultBrand
	}
	return s.brand
}

// SetBrandCache обновляет имя после сохранения в настройках.
func (s *Server) SetBrandCache(name string) {
	s.brandMu.Lock()
	defer s.brandMu.Unlock()
	s.brand = name
}

// Register вешает маршруты.
func (s *Server) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /static/{file}", s.serveAsset)
	mux.HandleFunc("GET /static/fonts/{file}", s.serveFont)

	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /login/totp", s.loginTOTP)
	mux.HandleFunc("POST /logout", s.guard(s.logout))

	mux.HandleFunc("GET /{$}", s.guard(s.dashboard))
	mux.HandleFunc("GET /users", s.guard(s.users))
	// Литеральный путь побеждает шаблон с {id}: «сироты» — не пользователь, а свой экран.
	mux.HandleFunc("GET /users/orphans", s.guard(s.orphans))
	mux.HandleFunc("GET /users/{id}", s.guard(s.users))
	mux.HandleFunc("GET /devices/{id}", s.guard(s.devicePage))
	mux.HandleFunc("GET /server", s.guard(s.serverPage))
	mux.HandleFunc("GET /servers/{slug}", s.guard(s.serverPage))
	mux.HandleFunc("GET /devices/{id}/config", s.guard(s.deviceConfig))
	mux.HandleFunc("GET /devices/{id}/conf", s.guard(s.deviceConfFile))
	mux.HandleFunc("GET /interfaces", s.guard(s.interfaces))
	mux.HandleFunc("GET /interfaces/{name}", s.guard(s.interfaces))
	mux.HandleFunc("GET /events", s.guard(s.events))
	mux.HandleFunc("GET /settings", s.guard(s.settings))

	// Живые фрагменты: тот же HTML, что на странице, но без каркаса (ТЗ §7.1).
	mux.HandleFunc("GET /live/dashboard", s.guard(s.liveDashboard))
	mux.HandleFunc("GET /live/users", s.guard(s.liveUsers))
	mux.HandleFunc("GET /live/users/{id}", s.guard(s.liveUser))
	mux.HandleFunc("GET /live/interfaces/{name}", s.guard(s.liveInterface))

	mux.HandleFunc("POST /users/new", s.guard(s.userCreate))
	mux.HandleFunc("POST /users/purge", s.guard(s.usersPurge))
	mux.HandleFunc("POST /users/{id}/update", s.guard(s.userUpdate))
	mux.HandleFunc("POST /users/{id}/status", s.guard(s.userStatus))
	mux.HandleFunc("POST /users/{id}/delete", s.guard(s.userDelete))
	mux.HandleFunc("POST /users/{id}/restore", s.guard(s.userRestore))
	mux.HandleFunc("POST /users/{id}/link", s.guard(s.userLink))
	mux.HandleFunc("POST /users/{id}/merge", s.guard(s.userMerge))
	mux.HandleFunc("GET /users/{id}/devices/new", s.guard(s.deviceNew))
	mux.HandleFunc("POST /users/{id}/devices/new", s.guard(s.deviceCreate))

	mux.HandleFunc("POST /devices/{id}/update", s.guard(s.deviceUpdate))
	mux.HandleFunc("POST /devices/{id}/status", s.guard(s.deviceStatus))
	mux.HandleFunc("POST /devices/{id}/delete", s.guard(s.deviceDelete))
	mux.HandleFunc("POST /devices/{id}/restore", s.guard(s.deviceRestore))
	mux.HandleFunc("POST /devices/{id}/rotate", s.guard(s.deviceRotate))
	mux.HandleFunc("POST /devices/{id}/move", s.guard(s.deviceMove))

	mux.HandleFunc("POST /servers/{slug}/retire", s.guard(s.serverRetire))
	mux.HandleFunc("POST /servers/{slug}/return", s.guard(s.serverReturn))
	mux.HandleFunc("POST /servers/{slug}/delete", s.guard(s.serverDelete))

	mux.HandleFunc("POST /interfaces/{name}/mode", s.guard(s.interfaceMode))
	mux.HandleFunc("POST /interfaces/{name}/reconcile", s.guard(s.interfaceReconcile))
	mux.HandleFunc("POST /interfaces/{name}/adopt", s.guard(s.peerAdopt))
	mux.HandleFunc("POST /interfaces/{name}/endpoints", s.guard(s.interfaceEndpoints))
	mux.HandleFunc("POST /interfaces/{name}/defaults", s.guard(s.interfaceDefaults))
	mux.HandleFunc("POST /interfaces/{name}/forget", s.guard(s.interfaceForget))

	mux.HandleFunc("POST /settings/totp/new", s.guard(s.totpNew))
	mux.HandleFunc("POST /settings/totp/enable", s.guard(s.totpEnable))
	mux.HandleFunc("POST /settings/totp/disable", s.guard(s.totpDisable))
	mux.HandleFunc("POST /settings/sessions/revoke", s.guard(s.sessionsRevoke))
	mux.HandleFunc("POST /settings/notify", s.guard(s.notifySave))
	mux.HandleFunc("POST /settings/brand", s.guard(s.brandSave))
	mux.HandleFunc("POST /settings/backup/now", s.guard(s.backupNow))
	// Ключи входа: регистрация — из панели, вход — со страницы входа (сессии там ещё нет).
	mux.HandleFunc("POST /settings/passkeys/begin", s.guard(s.passkeyRegisterBegin))
	mux.HandleFunc("POST /settings/passkeys/finish", s.guard(s.passkeyRegisterFinish))
	mux.HandleFunc("POST /settings/passkeys/{id}/delete", s.guard(s.passkeyDelete))
	mux.HandleFunc("POST /login/passkey/begin", s.passkeyLoginBegin)
	mux.HandleFunc("POST /login/passkey/finish", s.passkeyLoginFinish)

	s.registerPortal(mux)

	// Прежний адрес страницы наблюдения — теперь раздел «Интерфейсы».
	mux.HandleFunc("GET /observe/{iface}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/interfaces/"+r.PathValue("iface"), http.StatusMovedPermanently)
	})
}

func (s *Server) serveAsset(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("file")
	// Имя приходит с хэшем (app.<хэш>.css) — ищем по исходному имени и сверяем.
	for orig, a := range s.assets {
		if strings.TrimPrefix(a.name, "/static/") == name {
			w.Header().Set("Content-Type", a.ctype)
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			w.Write(a.body)
			return
		}
		if orig == name { // без хэша — отдаём, но без долгого кэша
			w.Header().Set("Content-Type", a.ctype)
			w.Header().Set("Cache-Control", "no-cache")
			w.Write(a.body)
			return
		}
	}
	http.NotFound(w, r)
}

// serveFont отдаёт файл шрифта: имя без хэша, зато содержимое неизменно и кэшируется на год.
func (s *Server) serveFont(w http.ResponseWriter, r *http.Request) {
	a, ok := s.assets["fonts/"+r.PathValue("file")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", a.ctype)
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Write(a.body)
}

// healthz открыт для внешнего сторожа: наружу — только факт жизни, версия, аптайм и время
// последней выборки. Текст последней ошибки (в нём бывают пути) — только локально.
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	st := s.Hub.Status()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	if s.isLocalHost(r) {
		fmt.Fprintf(w, `{"ok":true,"version":%q,"uptime":%q,"last_sample":%q,"last_error":%q}`+"\n", st.Version, st.Uptime, st.LastSample.Format(time.RFC3339), st.LastError)
		return
	}
	fmt.Fprintf(w, `{"ok":true,"version":%q,"uptime":%q,"last_sample":%q}`+"\n", st.Version, st.Uptime, st.LastSample.Format(time.RFC3339))
}

// Base — общая часть данных всех страниц: то, что рисует каркас.
type Base struct {
	Title string
	// Brand — как панель называет себя: вкладка браузера и левый верхний угол. Задаётся в
	// настройках, чтобы при развёртывании в другой среде панель звалась по-своему.
	Brand    string
	Section  string // dashboard | users | interfaces | events | settings
	Version  string
	Admin    string
	CSRF     string
	Now      time.Time
	CSS      []string
	JS       []string
	Server   string
	Online   int
	Peers    int
	Flash    string
	FlashErr string
	// Icon — значок сервиса во вкладке браузера.
	Icon string
}

func (s *Server) base(r *http.Request, sc *sessionCtx, title string) Base {
	b := Base{Title: title, Brand: s.Brand(), Version: version.Version, Now: time.Now(),
		CSS:  []string{s.asset("fonts.css"), s.asset("tokens.css"), s.asset("app.css")},
		JS:   []string{s.asset("live.js")},
		Icon: s.asset("icon.svg")}
	if r != nil {
		q := r.URL.Query()
		b.Flash, b.FlashErr = q.Get("ok"), q.Get("err")
	}
	if sc != nil {
		b.Admin = sc.Admin.Username
		b.CSRF = sc.Session.CSRF
	}
	st := s.Hub.Status()
	for id, n := range st.Peers {
		b.Peers += n
		b.Online += st.Online[id]
	}
	if s.Hub.Cfg != nil {
		b.Server = s.Hub.Cfg.ServerTitle
	}
	return b
}

func (s *Server) asset(name string) string {
	if a, ok := s.assets[name]; ok {
		return a.name
	}
	return "/static/" + name
}

// render собирает страницу в буфер и только потом отдаёт: ошибка шаблона на середине страницы
// иначе дописалась бы к уже отправленному телу, и в браузере получился бы мусор.
func (s *Server) render(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := s.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "шаблон "+name+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex")
	if w.Header().Get("Referrer-Policy") == "" {
		w.Header().Set("Referrer-Policy", "same-origin")
	}
	w.Write(buf.Bytes())
}

// renderPartial отдаёт один фрагмент страницы — то, что раз в 5 с забирает live.js.
func (s *Server) renderPartial(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := s.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "шаблон "+name+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(buf.Bytes())
}

// renderStatus — та же отрисовка, но с кодом ответа (страница входа после ошибки).
func (s *Server) renderStatus(w http.ResponseWriter, code int, name string, data any) {
	var buf bytes.Buffer
	if err := s.tpl.ExecuteTemplate(&buf, name, data); err != nil {
		http.Error(w, "шаблон "+name+": "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex")
	w.WriteHeader(code)
	w.Write(buf.Bytes())
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusInternalServerError)
}

// audit пишет запись журнала от лица администратора.
func (s *Server) audit(r *http.Request, actor, action, targetType string, targetID int64, details map[string]any) {
	s.Hub.Store.AddAudit(r.Context(), store.AuditEntry{
		Actor: actor, Action: action, TargetType: targetType, TargetID: targetID, Details: details, IP: s.clientIP(r),
	})
}

// ---------- ограничитель попыток входа ----------

type limiter struct {
	max   int
	block time.Duration

	mu    sync.Mutex
	fails map[string]*failState
}

type failState struct {
	count int
	until time.Time
}

func newLimiter(max int, block time.Duration) *limiter {
	return &limiter{max: max, block: block, fails: map[string]*failState{}}
}

func (l *limiter) blocked(key string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.fails[key]
	if f == nil || f.until.IsZero() {
		return 0, false
	}
	if d := time.Until(f.until); d > 0 {
		return d, true
	}
	f.until, f.count = time.Time{}, 0
	return 0, false
}

func (l *limiter) fail(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.fails[key]
	if f == nil {
		f = &failState{}
		l.fails[key] = f
	}
	f.count++
	if f.count >= l.max {
		f.until = time.Now().Add(l.block)
	}
}

func (l *limiter) reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.fails, key)
}

// clientIP берёт адрес клиента из хвоста X-Forwarded-For (FR-13.1b). Запросы приходят через
// SSH-туннель от прокси, поэтому RemoteAddr у всех одинаков — 127.0.0.1 — и настоящий адрес
// приносит обратный прокси. Заголовок присылает и сам клиент, причём его значение окажется
// в начале цепочки: прокси дописывает увиденный адрес в конец. Поэтому берётся ForwardedHops-й
// элемент с конца — тот, который добавил ближайший доверенный прокси. Прежняя версия читала
// начало цепочки, и любой запрос назначал себе адрес сам: ограничитель попыток входа обходился
// одной строкой заголовка, а в аудит попадал выдуманный IP.
func (s *Server) clientIP(r *http.Request) string {
	if s.ForwardedHops > 0 {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if i := len(parts) - s.ForwardedHops; i >= 0 {
				if v := strings.TrimSpace(parts[i]); v != "" {
					return v
				}
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func hostOnly(h string) string {
	if i := strings.IndexByte(h, ':'); i > 0 {
		return h[:i]
	}
	return h
}

func atoi64(s string) int64 {
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}
