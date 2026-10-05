package web

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/auth"
	"github.com/poznik/awgdash-pub/internal/store"
)

const (
	sessionCookie = "awgdash_session"
	pendingCookie = "awgdash_2fa"
	pendingTTL    = 5 * time.Minute
	// maxPasswordChecks — сколько проверок пароля идёт одновременно (FR-13.1d). argon2id держит
	// 64 МиБ на проверку, юнит живёт в 192 МБ: десяток параллельных попыток входа означал бы
	// OOM, причём для этого не нужно знать ни логина, ни пароля.
	maxPasswordChecks = 2
	// maxLoginBody, maxAdminBody — потолок тела запроса. Формы входа и портала короткие;
	// админские формы (endpoint'ы, разрешённые серверы) крупнее, но и им хватает мегабайта.
	maxLoginBody = 64 << 10
	maxAdminBody = 1 << 20
	// maxUsernameRunes — длиннее имени администратора не бывает, а в журнал попадает присланное.
	maxUsernameRunes = 64
)

// limitBody ограничивает тело запроса: без потолка одна форма приносит до 10 МБ (умолчание
// ParseForm), и всё это уходит в разбор, а с неудачного входа — ещё и в журнал.
func limitBody(w http.ResponseWriter, r *http.Request, n int64) {
	r.Body = http.MaxBytesReader(w, r.Body, n)
}

// holdPasswordSlot занимает место в очереди на проверку пароля; false означает «занято».
func (s *Server) holdPasswordSlot() bool {
	select {
	case s.pwSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (s *Server) releasePasswordSlot() { <-s.pwSlots }

// Session — вход администратора, доступный обработчикам через контекст запроса.
type sessionCtx struct {
	Session store.Session
	Admin   store.Admin
}

// setCookie кладёт куку с разумными флагами. Secure ставится только на публичном имени:
// при работе через `ssh -L` панель открывается по http://localhost, и Secure выкинул бы вход.
func (s *Server) setCookie(w http.ResponseWriter, r *http.Request, name, value string, ttl time.Duration) {
	c := &http.Cookie{
		Name: name, Value: value, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Через обратный прокси панель работает по https, локально через туннель — по http; смотрим на имя,
		// по которому обратился браузер, иначе кука либо не поставится, либо уедет без Secure.
		Secure: !s.isLocalHost(r),
	}
	if ttl > 0 {
		c.Expires = time.Now().Add(ttl)
		c.MaxAge = int(ttl.Seconds())
	} else {
		c.MaxAge = -1
	}
	http.SetCookie(w, c)
}

func (s *Server) isLocalHost(r *http.Request) bool {
	return localName(hostOnly(s.requestHost(r)))
}

func localName(host string) bool {
	h := strings.ToLower(host)
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
}

// requestHost — имя, по которому браузер обратился к панели. За обратным прокси в r.Host
// лежит localhost:10088, а настоящее имя приходит в X-Forwarded-Host. Заголовок принимается,
// только когда он называет одно из известных панели имён (FR-13.1c): от этого имени зависят
// проверка Host, проверка источника, RPID ключей входа и флаг Secure у куки, и произвольное
// значение от клиента здесь брать нельзя.
func (s *Server) requestHost(r *http.Request) string {
	if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
		if i := strings.IndexByte(xfh, ','); i > 0 {
			xfh = xfh[:i]
		}
		if xfh = strings.TrimSpace(xfh); s.knownName(xfh) {
			return xfh
		}
	}
	return r.Host
}

// knownName — имя, которое панель признаёт своим: админка, портал или localhost (SSH-туннель).
// Когда оба имени не заданы (разработка, стенд), панель имён не различает и признаёт любое.
func (s *Server) knownName(h string) bool {
	host := hostOnly(h)
	if host == "" {
		return false
	}
	if localName(host) {
		return true
	}
	if s.AdminHost == "" && s.PortalHost == "" {
		return true
	}
	return (s.AdminHost != "" && strings.EqualFold(host, hostOnly(s.AdminHost))) ||
		(s.PortalHost != "" && strings.EqualFold(host, hostOnly(s.PortalHost)))
}

// forwardedOK — прокси назвал имя, которое панель знает. Неизвестное имя в заголовке означает
// запрос мимо обычного пути: панель на него не отвечает вовсе, вместо того чтобы принять
// присланное значение за своё имя (FR-13.1c).
func (s *Server) forwardedOK(r *http.Request) bool {
	xfh := r.Header.Get("X-Forwarded-Host")
	if xfh == "" {
		return true
	}
	if i := strings.IndexByte(xfh, ','); i > 0 {
		xfh = xfh[:i]
	}
	return s.knownName(strings.TrimSpace(xfh))
}

// currentSession читает куку и возвращает живую сессию с администратором.
func (s *Server) currentSession(r *http.Request) (sessionCtx, error) {
	c, err := r.Cookie(sessionCookie)
	if err != nil {
		return sessionCtx{}, store.ErrNotFound
	}
	ses, err := s.Hub.Store.SessionByID(r.Context(), c.Value)
	if err != nil {
		return sessionCtx{}, err
	}
	admin, err := s.Hub.Store.AdminByID(r.Context(), ses.AdminID)
	if err != nil {
		return sessionCtx{}, err
	}
	s.Hub.Store.TouchSession(r.Context(), ses)
	return sessionCtx{Session: ses, Admin: admin}, nil
}

// guard — обёртка админских страниц: проверка Host, живой сессии и CSRF на изменяющих запросах.
func (s *Server) guard(h func(http.ResponseWriter, *http.Request, sessionCtx)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.hostAllowed(r) {
			http.NotFound(w, r)
			return
		}
		sc, err := s.currentSession(r)
		if err != nil {
			if r.Method != http.MethodGet {
				http.Error(w, "сессия истекла, войдите заново", http.StatusUnauthorized)
				return
			}
			http.Redirect(w, r, "/login?next="+urlQueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			limitBody(w, r, maxAdminBody)
			if err := s.checkCSRF(r, sc); err != nil {
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
		}
		w.Header().Set("Cache-Control", "no-store")
		// same-origin, а не no-referrer: при no-referrer браузер шлёт Origin: null даже своим же
		// формам, и проверка источника отбивала кнопки самой панели. Наружу referrer всё равно
		// не уходит, а в адресах админки секретов нет.
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		h(w, r, sc)
	}
}

// checkCSRF сверяет токен формы с токеном сессии и происхождение запроса: форма панели
// приходит только со своей же страницы.
func (s *Server) checkCSRF(r *http.Request, sc sessionCtx) error {
	if err := r.ParseForm(); err != nil {
		return fmt.Errorf("не разобрана форма: %w", err)
	}
	token := r.PostFormValue("csrf")
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(sc.Session.CSRF)) != 1 {
		return errors.New("не сходится CSRF-токен — обновите страницу")
	}
	return s.checkOrigin(r)
}

// checkOrigin — вторая линия после CSRF-токена. Сообщение называет, что именно не сошлось:
// панель стоит за прокси, и разбирать такие отказы вслепую слишком дорого.
func (s *Server) checkOrigin(r *http.Request) error {
	site := r.Header.Get("Sec-Fetch-Site")
	origin := r.Header.Get("Origin")
	if site != "" && site != "same-origin" && site != "none" {
		s.logOriginRefusal(r, "Sec-Fetch-Site="+site)
		return fmt.Errorf("браузер сообщил, что запрос межсайтовый (Sec-Fetch-Site: %s)", site)
	}
	// Origin: null браузер присылает, когда источник намеренно скрыт — например, при
	// Referrer-Policy: no-referrer на странице портала. Это «источник не сообщён», а не «чужой»:
	// от подделки здесь защищают CSRF-токен админки и секретный адрес портала.
	if origin == "null" {
		origin = ""
	}
	if origin != "" && !s.sameOrigin(origin, r) {
		s.logOriginRefusal(r, "Origin="+origin)
		return fmt.Errorf("не сходится источник запроса: Origin %s, а панель знает имена %s", origin, strings.Join(s.knownHosts(r), ", "))
	}
	return nil
}

// logOriginRefusal кладёт в журнал всё, что нужно, чтобы понять отказ: какие имена видит панель
// и что прислал прокси. Секретов здесь нет — только имена и путь.
func (s *Server) logOriginRefusal(r *http.Request, reason string) {
	if s.Hub == nil || s.Hub.Log == nil {
		return
	}
	s.Hub.Log.Warn("запрос отклонён проверкой источника",
		"причина", reason, "path", r.URL.Path, "host", r.Host,
		"x_forwarded_host", r.Header.Get("X-Forwarded-Host"),
		"x_forwarded_proto", r.Header.Get("X-Forwarded-Proto"),
		"origin", r.Header.Get("Origin"), "referer", r.Header.Get("Referer"),
		"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"),
		"известные_имена", strings.Join(s.knownHosts(r), ","))
}

// knownHosts — имена, которые панель считает своими.
func (s *Server) knownHosts(r *http.Request) []string {
	out := []string{}
	for _, h := range []string{s.requestHost(r), r.Host, s.AdminHost, s.PortalHost} {
		if h == "" {
			continue
		}
		dup := false
		for _, seen := range out {
			if seen == h {
				dup = true
			}
		}
		if !dup {
			out = append(out, h)
		}
	}
	return out
}

// sameOrigin — пришёл ли запрос с одной из наших страниц. Сравнивать Origin с r.Host нельзя:
// обратный прокси подменяет Host на localhost:10088, и браузерный Origin с внешним именем
// перестаёт совпадать — в панели от этого переставали работать все кнопки.
func (s *Server) sameOrigin(origin string, r *http.Request) bool {
	origin = strings.ToLower(strings.TrimSuffix(origin, "/"))
	hosts := []string{s.requestHost(r), r.Host, s.AdminHost, s.PortalHost}
	for _, h := range hosts {
		if h == "" {
			continue
		}
		for _, scheme := range []string{"https://", "http://"} {
			if origin == strings.ToLower(scheme+h) || origin == strings.ToLower(scheme+hostOnly(h)) {
				return true
			}
		}
	}
	// Локальная работа через `ssh -L`: имя localhost с любым портом.
	host := hostOnly(strings.TrimPrefix(strings.TrimPrefix(origin, "https://"), "http://"))
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// hostAllowed — админка отвечает только на своём имени и на localhost (SSH-туннель).
func (s *Server) hostAllowed(r *http.Request) bool {
	if !s.forwardedOK(r) {
		return false
	}
	host := hostOnly(s.requestHost(r))
	if host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return true
	}
	if s.AdminHost == "" {
		return true
	}
	return strings.EqualFold(host, s.AdminHost)
}

// ---------- вход ----------

type loginData struct {
	Base
	Next         string
	Error        string
	Stage        string // password | totp
	Pending      string
	User         string
	HasPasskeys  bool // кнопку «войти по ключу» показываем, только если ключи заведены
	PasswordOpen bool // форма логина раскрыта: ключей нет или вход паролем уже не удался
}

// loginBase — оформление страницы входа: живых блоков там нет, зато нужен вход по ключу.
func (s *Server) loginBase(r *http.Request, title string) Base {
	b := s.base(r, nil, title)
	b.JS = []string{s.asset("passkey.js")}
	return b
}

// hasPasskeys — есть ли ключ, годный для того имени, по которому открыта панель.
func (s *Server) hasPasskeys(r *http.Request) bool {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	n, err := s.Hub.Store.CountPasskeys(ctx, hostOnly(s.requestHost(r)))
	return err == nil && n > 0
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	if !s.hostAllowed(r) {
		http.NotFound(w, r)
		return
	}
	if _, err := s.currentSession(r); err == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	// Страница входа не проходит через guard, а заголовок нужен и ей.
	w.Header().Set("X-Content-Type-Options", "nosniff")
	keys := s.hasPasskeys(r)
	s.render(w, "login.html", loginData{Base: s.loginBase(r, "Вход"), Next: r.URL.Query().Get("next"), Stage: "password",
		HasPasskeys: keys, PasswordOpen: !keys})
}

// loginSubmit — первый шаг: логин и пароль. Если у администратора включён второй фактор,
// сессия ещё не выдаётся: подписанная кука помнит, кто прошёл пароль, ровно pendingTTL.
func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	if !s.hostAllowed(r) {
		http.NotFound(w, r)
		return
	}
	limitBody(w, r, maxLoginBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "не разобрана форма", http.StatusBadRequest)
		return
	}
	next := r.PostFormValue("next")
	ip := s.clientIP(r)
	if wait, blocked := s.Login.blocked(ip); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())))
		s.renderLoginError(w, r, "password", "", "", "слишком много попыток, подождите "+wait.Round(time.Second).String(), next)
		return
	}
	// Очередь на argon2id: пока свободного места нет, панель отвечает отказом вместо того,
	// чтобы занимать память под ещё одну проверку (FR-13.1d).
	if !s.holdPasswordSlot() {
		w.Header().Set("Retry-After", "2")
		s.renderLoginBusy(w, r, next)
		return
	}
	defer s.releasePasswordSlot()
	// Имя обрезается до записи в журнал: присланное значение попадает в аудит неудачного входа.
	username := store.TrimRunes(strings.TrimSpace(r.PostFormValue("username")), maxUsernameRunes)
	password := r.PostFormValue("password")
	admin, err := s.Hub.Store.AdminByUsername(r.Context(), username)
	// Пароль проверяется даже для несуществующего имени: иначе время ответа выдаёт, кто заведён.
	hash := admin.PasswordHash
	if err != nil {
		hash = "$argon2id$v=19$m=65536,t=2,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	ok := auth.VerifyPassword(hash, password) && err == nil
	if !ok {
		s.Login.fail(ip)
		time.Sleep(400 * time.Millisecond)
		s.audit(r, store.ActorSystem, "admin.login_failed", "admin", 0, map[string]any{"username": username})
		s.renderLoginError(w, r, "password", "", username, "неверный логин или пароль", next)
		return
	}
	if admin.TOTPEnabled {
		token, err := s.signPending(admin.ID)
		if err != nil {
			s.fail(w, err)
			return
		}
		s.setCookie(w, r, pendingCookie, token, pendingTTL)
		s.render(w, "login.html", loginData{Base: s.base(r, nil, "Вход"), Stage: "totp", User: admin.Username, Next: next})
		return
	}
	s.startSession(w, r, admin, next)
}

// loginTOTP — второй шаг: код из приложения.
func (s *Server) loginTOTP(w http.ResponseWriter, r *http.Request) {
	if !s.hostAllowed(r) {
		http.NotFound(w, r)
		return
	}
	limitBody(w, r, maxLoginBody)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "не разобрана форма", http.StatusBadRequest)
		return
	}
	next := r.PostFormValue("next")
	ip := s.clientIP(r)
	if wait, blocked := s.Login.blocked(ip); blocked {
		s.renderLoginError(w, r, "password", "", "", "слишком много попыток, подождите "+wait.Round(time.Second).String(), next)
		return
	}
	c, err := r.Cookie(pendingCookie)
	if err != nil {
		s.renderLoginError(w, r, "password", "", "", "шаг подтверждения просрочен — войдите заново", next)
		return
	}
	adminID, ok := s.verifyPending(c.Value)
	if !ok {
		s.setCookie(w, r, pendingCookie, "", 0)
		s.renderLoginError(w, r, "password", "", "", "шаг подтверждения просрочен — войдите заново", next)
		return
	}
	admin, err := s.Hub.Store.AdminByID(r.Context(), adminID)
	if err != nil {
		s.renderLoginError(w, r, "password", "", "", "войдите заново", next)
		return
	}
	if !auth.VerifyTOTP(admin.TOTPSecret, r.PostFormValue("code"), time.Now()) {
		s.Login.fail(ip)
		time.Sleep(400 * time.Millisecond)
		s.audit(r, store.ActorSystem, "admin.totp_failed", "admin", admin.ID, map[string]any{"username": admin.Username})
		s.renderLoginError(w, r, "totp", admin.Username, admin.Username, "код не подошёл", next)
		return
	}
	s.setCookie(w, r, pendingCookie, "", 0)
	s.startSession(w, r, admin, next)
}

// issueSession открывает сессию и ставит куку. Отдельно от startSession, потому что вход
// по ключу отвечает браузеру не редиректом, а JSON.
func (s *Server) issueSession(w http.ResponseWriter, r *http.Request, admin store.Admin) error {
	ses, err := s.Hub.Store.CreateSession(r.Context(), admin.ID, s.clientIP(r), r.UserAgent())
	if err != nil {
		return err
	}
	s.Login.reset(s.clientIP(r))
	s.Hub.Store.TouchLogin(r.Context(), admin.ID)
	s.audit(r, store.ActorAdmin, "admin.login", "admin", admin.ID, map[string]any{"username": admin.Username})
	s.setCookie(w, r, sessionCookie, ses.ID, store.SessionTTL)
	return nil
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, admin store.Admin, next string) {
	if err := s.issueSession(w, r, admin); err != nil {
		s.fail(w, err)
		return
	}
	http.Redirect(w, r, safeNext(next), http.StatusSeeOther)
}

// safeNext пропускает только путь внутри самой панели. Открытый редирект на чужой домен —
// готовый фишинг: ссылка «наша», а после ввода пароля браузер уходит на копию панели.
// Отвергается всё, что браузер способен прочитать как абсолютный адрес: `//host`, `/\host`
// (обратный слэш нормализуется в прямой), `%2f%2fhost` (раскодируется в `//`) и схема с `:`.
func safeNext(next string) string {
	if next == "" || next[0] != '/' {
		return "/"
	}
	lower := strings.ToLower(next)
	if strings.ContainsAny(next, "\\") || strings.Contains(next, ":") ||
		strings.HasPrefix(next, "//") || strings.HasPrefix(lower, "/%2f") || strings.HasPrefix(lower, "/%5c") {
		return "/"
	}
	// Разбор снимает остаток случаев (управляющие символы, экзотика) — берём только путь и запрос.
	u, err := url.Parse(next)
	if err != nil || u.IsAbs() || u.Host != "" {
		return "/"
	}
	out := u.EscapedPath()
	if out == "" {
		return "/"
	}
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// renderLoginBusy — очередь на проверку пароля занята. Отдельный код ответа: это не отказ
// во входе, а просьба повторить через пару секунд.
func (s *Server) renderLoginBusy(w http.ResponseWriter, r *http.Request, next string) {
	s.renderStatus(w, http.StatusTooManyRequests, "login.html", loginData{Base: s.loginBase(r, "Вход"), Stage: "password",
		Error: "панель занята проверкой других попыток входа — повторите через пару секунд", Next: next,
		HasPasskeys: s.hasPasskeys(r), PasswordOpen: true})
}

func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, stage, user, username, msg, next string) {
	// Ошибку показываем над раскрытой формой: сообщение над закрытой выглядело бы беспричинным.
	s.renderStatus(w, http.StatusUnauthorized, "login.html", loginData{Base: s.loginBase(r, "Вход"), Stage: stage,
		User: user, Error: msg, Next: next, HasPasskeys: s.hasPasskeys(r), PasswordOpen: true})
}

// logout закрывает текущую сессию.
func (s *Server) logout(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	s.Hub.Store.DeleteSession(r.Context(), sc.Session.ID)
	s.audit(r, store.ActorAdmin, "admin.logout", "admin", sc.Admin.ID, map[string]any{"username": sc.Admin.Username})
	s.setCookie(w, r, sessionCookie, "", 0)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---------- подписанная кука промежуточного шага ----------

// signPending подписывает «этот админ прошёл пароль» ключом сессий; без ключа второй фактор
// не включается (панель об этом скажет в doctor).
func (s *Server) signPending(adminID int64) (string, error) {
	if len(s.SessionKey) == 0 {
		return "", errors.New("AWGDASH_SESSION_KEY не задан — второй фактор работать не может")
	}
	payload := fmt.Sprintf("%d.%d", adminID, time.Now().Add(pendingTTL).Unix())
	mac := hmac.New(sha256.New, s.SessionKey)
	mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

func (s *Server) verifyPending(token string) (int64, bool) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || len(s.SessionKey) == 0 {
		return 0, false
	}
	payload := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, s.SessionKey)
	mac.Write([]byte(payload))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if subtle.ConstantTimeCompare([]byte(parts[2]), []byte(want)) != 1 {
		return 0, false
	}
	adminID, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, false
	}
	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return 0, false
	}
	return adminID, true
}

func urlQueryEscape(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "&", "%26"), "?", "%3F")
}
