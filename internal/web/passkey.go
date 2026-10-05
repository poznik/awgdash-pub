package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/poznik/awgdash-pub/internal/auth"
	"github.com/poznik/awgdash-pub/internal/store"
)

// Вход по ключу (passkey): Windows Hello, Touch ID, Face ID. Ключ живёт на устройстве, панель
// хранит только публичную часть. Пароль и второй фактор остаются запасным путём (SPEC FR-13.1).

const (
	// waCookie помнит, какой челлендж выдан этому браузеру: сам челлендж лежит на сервере.
	waCookie = "awgdash_wa"
	// waTTL — сколько ждать, пока человек приложит палец или введёт PIN.
	waTTL = 5 * time.Minute
)

// waSessions — челленджи, ожидающие ответа. Панель однопроцессная, поэтому хватает памяти:
// переживать перезапуск незачем, незаконченная попытка входа просто повторяется.
type waSessions struct {
	mu sync.Mutex
	m  map[string]waEntry
}

type waEntry struct {
	data    webauthn.SessionData
	adminID int64 // для регистрации: чей ключ заводим
	expires time.Time
}

func newWASessions() *waSessions { return &waSessions{m: map[string]waEntry{}} }

func (s *waSessions) put(data webauthn.SessionData, adminID int64) (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	id := base64.RawURLEncoding.EncodeToString(buf)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.m { // попутная уборка: незаконченные попытки не должны копиться
		if now.After(v.expires) {
			delete(s.m, k)
		}
	}
	s.m[id] = waEntry{data: data, adminID: adminID, expires: now.Add(waTTL)}
	return id, nil
}

func (s *waSessions) take(id string) (waEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.m[id]
	delete(s.m, id) // челлендж одноразовый
	if !ok || time.Now().After(e.expires) {
		return waEntry{}, false
	}
	return e, true
}

// webauthnFor собирает проверяющего под то имя, по которому браузер открыл панель: RPID и origin
// обязаны совпасть с адресной строкой, иначе подпись не примут. Через туннель это localhost,
// снаружи — публичное имя.
func (s *Server) webauthnFor(r *http.Request) (*webauthn.WebAuthn, error) {
	host := s.requestHost(r)
	scheme := "https"
	if s.isLocalHost(r) {
		scheme = "http"
	}
	return auth.NewWebAuthn(hostOnly(host), scheme+"://"+host)
}

// passkeyUser собирает представление администратора со всеми его ключами.
func (s *Server) passkeyUser(ctx context.Context, admin store.Admin) (*auth.PasskeyUser, error) {
	handle, err := s.Hub.Store.WebAuthnHandle(ctx, admin.ID)
	if err != nil {
		return nil, err
	}
	keys, err := s.Hub.Store.Passkeys(ctx, admin.ID)
	if err != nil {
		return nil, err
	}
	u := &auth.PasskeyUser{Handle: []byte(handle), Login: admin.Username, Display: admin.Username}
	for _, k := range keys {
		c, err := auth.ToCredential(k)
		if err != nil {
			return nil, err
		}
		u.Credentials = append(u.Credentials, c)
	}
	return u, nil
}

// ---------- регистрация ключа ----------

// passkeyRegisterBegin выдаёт браузеру задание завести ключ. Требуется живая сессия: ключ
// заводится тому, кто уже вошёл паролем.
func (s *Server) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	wa, err := s.webauthnFor(r)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err)
		return
	}
	user, err := s.passkeyUser(ctx, sc.Admin)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err)
		return
	}
	creation, data, err := wa.BeginRegistration(user, auth.RegistrationOptions(user.Credentials)...)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err)
		return
	}
	id, err := s.WA.put(*data, sc.Admin.ID)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err)
		return
	}
	s.setCookie(w, r, waCookie, id, waTTL)
	s.writeJSON(w, creation)
}

// passkeyRegisterFinish проверяет ответ устройства и сохраняет ключ.
func (s *Server) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	entry, ok := s.takeWASession(r)
	if !ok || entry.adminID != sc.Admin.ID {
		s.jsonError(w, http.StatusBadRequest, errors.New("попытка устарела — начните заново"))
		return
	}
	wa, err := s.webauthnFor(r)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err)
		return
	}
	user, err := s.passkeyUser(ctx, sc.Admin)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err)
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	cred, err := wa.FinishRegistration(user, entry.data, r)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err)
		return
	}
	if name == "" {
		name = "ключ"
	}
	if len([]rune(name)) > 32 {
		name = string([]rune(name)[:32])
	}
	key := auth.FromCredential(sc.Admin.ID, cred, name)
	key.RPID = hostOnly(s.requestHost(r))
	if _, err := s.Hub.Store.AddPasskey(ctx, key); err != nil {
		s.jsonError(w, http.StatusInternalServerError, err)
		return
	}
	s.audit(r, store.ActorAdmin, "admin.passkey_add", "admin", sc.Admin.ID, map[string]any{"name": name})
	s.writeJSON(w, map[string]any{"ok": true, "next": "/settings"})
}

// passkeyDelete убирает ключ. Последний ключ удалить можно: пароль и второй фактор никуда
// не делись, вход останется.
func (s *Server) passkeyDelete(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	id := atoi64(r.PathValue("id"))
	if err := s.Hub.Store.DeletePasskey(ctx, id, sc.Admin.ID); err != nil {
		s.back(w, r, "/settings", err)
		return
	}
	s.audit(r, store.ActorAdmin, "admin.passkey_delete", "admin", sc.Admin.ID, map[string]any{"passkey": id})
	s.done(w, r, "/settings", "ключ удалён")
}

// ---------- вход по ключу ----------

// passkeyLoginBegin выдаёт челлендж без имени пользователя: браузер сам предложит подходящий
// ключ из тех, что заведены для этой панели.
func (s *Server) passkeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !s.hostAllowed(r) {
		http.NotFound(w, r)
		return
	}
	limitBody(w, r, maxLoginBody)
	if err := s.checkOrigin(r); err != nil {
		s.jsonError(w, http.StatusForbidden, err)
		return
	}
	wa, err := s.webauthnFor(r)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err)
		return
	}
	assertion, data, err := wa.BeginDiscoverableLogin(auth.LoginOptions()...)
	if err != nil {
		s.jsonError(w, http.StatusBadRequest, err)
		return
	}
	id, err := s.WA.put(*data, 0)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err)
		return
	}
	s.setCookie(w, r, waCookie, id, waTTL)
	s.writeJSON(w, assertion)
}

// passkeyLoginFinish проверяет подпись и открывает сессию. Ограничитель попыток здесь тот же,
// что и у пароля: подобрать ключ нельзя, но и молотить запросами по панели незачем.
func (s *Server) passkeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if !s.hostAllowed(r) {
		http.NotFound(w, r)
		return
	}
	limitBody(w, r, maxLoginBody)
	if err := s.checkOrigin(r); err != nil {
		s.jsonError(w, http.StatusForbidden, err)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	ip := s.clientIP(r)
	if wait, blocked := s.Login.blocked(ip); blocked {
		s.jsonError(w, http.StatusTooManyRequests, fmt.Errorf("слишком много попыток, подождите %s", wait.Round(time.Second)))
		return
	}
	entry, ok := s.takeWASession(r)
	if !ok {
		s.jsonError(w, http.StatusBadRequest, errors.New("попытка устарела — начните заново"))
		return
	}
	wa, err := s.webauthnFor(r)
	if err != nil {
		s.jsonError(w, http.StatusInternalServerError, err)
		return
	}
	var admin store.Admin
	handler := func(rawID, userHandle []byte) (webauthn.User, error) {
		a, err := s.Hub.Store.AdminByWebAuthnHandle(ctx, string(userHandle))
		if err != nil {
			return nil, fmt.Errorf("ключ не привязан к администратору: %w", err)
		}
		admin = a
		return s.passkeyUser(ctx, a)
	}
	cred, err := wa.FinishDiscoverableLogin(handler, entry.data, r)
	if err != nil {
		s.Login.fail(ip)
		s.jsonError(w, http.StatusUnauthorized, err)
		return
	}
	key, err := s.Hub.Store.PasskeyByCredential(ctx, auth.CredentialIDOf(cred))
	if err != nil {
		s.jsonError(w, http.StatusUnauthorized, errors.New("ключ не найден"))
		return
	}
	// Счётчик подписей, который пошёл назад, означает копию ключа. Аутентификаторы Apple и
	// Windows его не ведут (всегда 0) — тогда сравнивать нечего.
	if cred.Authenticator.CloneWarning {
		s.Hub.Store.AddEvent(ctx, store.Event{Kind: "passkey_clone", Severity: "crit",
			Message: fmt.Sprintf("ключ «%s» прислал счётчик меньше сохранённого — возможна копия", key.Name)})
	}
	s.Hub.Store.TouchPasskey(ctx, key.ID, cred.Authenticator.SignCount)
	if err := s.issueSession(w, r, admin); err != nil {
		s.jsonError(w, http.StatusInternalServerError, err)
		return
	}
	s.writeJSON(w, map[string]any{"ok": true, "next": safeNext(r.URL.Query().Get("next"))})
}

func (s *Server) takeWASession(r *http.Request) (waEntry, bool) {
	c, err := r.Cookie(waCookie)
	if err != nil || c.Value == "" {
		return waEntry{}, false
	}
	return s.WA.take(c.Value)
}

func (s *Server) writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(v); err != nil && s.Hub != nil && s.Hub.Log != nil {
		s.Hub.Log.Warn("ответ JSON", "err", err)
	}
}

// jsonError отвечает машине и человеку одновременно: текст показывается на странице входа.
func (s *Server) jsonError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]any{"error": err.Error()})
}
