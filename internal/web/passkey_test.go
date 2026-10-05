package web

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/poznik/awgdash-pub/internal/store"
)

// Вход по ключу начинается с челленджа и одноразовой куки.
func TestPasskeyLoginBeginGivesChallenge(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("POST", e.srv.URL+"/login/passkey/begin", nil)
	req.Host = "panel.example.com"
	resp, body := e.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("код %d: %s", resp.StatusCode, body)
	}
	var out struct {
		PublicKey struct {
			Challenge        string `json:"challenge"`
			UserVerification string `json:"userVerification"`
			RPID             string `json:"rpId"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("ответ не разобран: %v (%s)", err, body)
	}
	if len(out.PublicKey.Challenge) < 20 {
		t.Fatalf("челлендж короткий: %q", out.PublicKey.Challenge)
	}
	if out.PublicKey.UserVerification != "required" {
		t.Fatalf("проверка пользователя не обязательна: %q", out.PublicKey.UserVerification)
	}
	if out.PublicKey.RPID != "panel.example.com" {
		t.Fatalf("RPID %q не совпадает с именем панели", out.PublicKey.RPID)
	}
	if !strings.Contains(resp.Header.Get("Set-Cookie"), waCookie) {
		t.Fatalf("кука попытки не поставлена: %q", resp.Header.Get("Set-Cookie"))
	}
}

// Без куки попытки завершение входа отвечает понятной ошибкой, а не паникой.
func TestPasskeyLoginFinishWithoutChallenge(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("POST", e.srv.URL+"/login/passkey/finish", strings.NewReader("{}"))
	req.Host = "panel.example.com"
	req.Header.Set("Content-Type", "application/json")
	resp, body := e.do(t, req)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("код %d, ожидался 400: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "устарела") {
		t.Fatalf("невнятный ответ: %s", body)
	}
}

// Челлендж одноразовый: повторно тот же идентификатор не принимается.
func TestPasskeyChallengeIsSingleUse(t *testing.T) {
	s := newWASessions()
	id, err := s.put(webauthn.SessionData{Challenge: "abc"}, 7)
	if err != nil {
		t.Fatal(err)
	}
	e, ok := s.take(id)
	if !ok || e.adminID != 7 {
		t.Fatalf("первая попытка не найдена: %+v", e)
	}
	if _, ok := s.take(id); ok {
		t.Fatal("челлендж принят повторно")
	}
}

// Регистрация ключа требует входа: без сессии — 401, с сессией — задание браузеру.
func TestPasskeyRegisterNeedsSession(t *testing.T) {
	e := newEnv(t)
	req, _ := http.NewRequest("POST", e.srv.URL+"/settings/passkeys/begin", nil)
	resp, _ := e.do(t, req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("без сессии код %d, ожидался 401", resp.StatusCode)
	}

	csrf := e.login(t)
	req, _ = http.NewRequest("POST", e.srv.URL+"/settings/passkeys/begin", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	resp, body := e.do(t, req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("код %d: %s", resp.StatusCode, body)
	}
	var out struct {
		PublicKey struct {
			User struct {
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"user"`
			AuthenticatorSelection struct {
				ResidentKey      string `json:"residentKey"`
				UserVerification string `json:"userVerification"`
			} `json:"authenticatorSelection"`
		} `json:"publicKey"`
	}
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("ответ не разобран: %v (%s)", err, body)
	}
	if out.PublicKey.User.Name != "admin" {
		t.Fatalf("имя администратора не подставлено: %q", out.PublicKey.User.Name)
	}
	if out.PublicKey.User.ID == "" {
		t.Fatal("не выдан идентификатор пользователя (handle)")
	}
	if out.PublicKey.AuthenticatorSelection.ResidentKey != "required" {
		t.Fatalf("ключ не резидентный (%q) — вход без логина не сработает", out.PublicKey.AuthenticatorSelection.ResidentKey)
	}
	if out.PublicKey.AuthenticatorSelection.UserVerification != "required" {
		t.Fatalf("проверка пользователя не обязательна: %q", out.PublicKey.AuthenticatorSelection.UserVerification)
	}
	// Handle должен быть постоянным: второй запрос выдаёт тот же идентификатор.
	first := out.PublicKey.User.ID
	req, _ = http.NewRequest("POST", e.srv.URL+"/settings/passkeys/begin", nil)
	req.Header.Set("X-CSRF-Token", csrf)
	_, body = e.do(t, req)
	json.Unmarshal([]byte(body), &out)
	if out.PublicKey.User.ID != first {
		t.Fatalf("handle меняется между попытками: %q → %q", first, out.PublicKey.User.ID)
	}
}

// Кнопка входа по ключу появляется, только когда ключи заведены.
func TestLoginPageShowsPasskeyButtonOnlyWithKeys(t *testing.T) {
	e := newEnv(t)
	// Ключ привязан к имени панели, поэтому и страницу запрашиваем по этому имени.
	_, body := e.withHost(t, "panel.example.com", "/login")
	if strings.Contains(body, "passkey-login") {
		t.Fatal("кнопка входа по ключу показана, хотя ключей нет")
	}
	if _, err := e.store.AddPasskey(t.Context(), passkeyFixture(e.admin.ID)); err != nil {
		t.Fatal(err)
	}
	_, body = e.withHost(t, "panel.example.com", "/login")
	if !strings.Contains(body, "passkey-login") {
		t.Fatal("кнопка входа по ключу не появилась")
	}
	// В ссылке на скрипт стоит хэш содержимого, поэтому ищем по началу имени.
	if !strings.Contains(body, "/static/passkey.") {
		t.Fatal("скрипт входа по ключу не подключён")
	}
}

// passkeyFixture — правдоподобная запись ключа для тестов, которым важно лишь его наличие.
func passkeyFixture(adminID int64) store.Passkey {
	return store.Passkey{
		AdminID:      adminID,
		CredentialID: "0PQRstuVWXyz0123456789ab",
		PublicKey:    []byte{0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01},
		Name:         "ноутбук",
		RPID:         "panel.example.com",
	}
}

// Ключ — главный способ входа: кнопка стоит выше формы, а форма логина свёрнута.
// Без ключей форма раскрыта сразу, иначе войти было бы нечем.
func TestLoginPageOrdersPasskeyFirst(t *testing.T) {
	e := newEnv(t)
	_, body := e.withHost(t, "panel.example.com", "/login")
	if !strings.Contains(body, `id="pw-details" open`) {
		t.Fatal("без ключей форма логина должна быть раскрыта")
	}
	if _, err := e.store.AddPasskey(t.Context(), passkeyFixture(e.admin.ID)); err != nil {
		t.Fatal(err)
	}
	_, body = e.withHost(t, "panel.example.com", "/login")
	if strings.Contains(body, `id="pw-details" open`) {
		t.Fatal("при заведённом ключе форма логина должна быть свёрнута")
	}
	if !strings.Contains(body, "Войти по логину и паролю") {
		t.Fatal("нет ссылки на вход паролем")
	}
	btn := strings.Index(body, `id="passkey-login"`)
	form := strings.Index(body, `id="pw-details"`)
	if btn < 0 || form < 0 || btn > form {
		t.Fatalf("кнопка ключа должна идти перед формой логина (кнопка %d, форма %d)", btn, form)
	}
	// Поля логина остаются в разметке: свёрнутая форма доступна по одному клику и без JS.
	if !strings.Contains(body, `name="password"`) {
		t.Fatal("форма логина исчезла из страницы")
	}
}

// После неудачного пароля форма остаётся раскрытой — иначе сообщение висит над пустотой.
func TestLoginErrorKeepsPasswordFormOpen(t *testing.T) {
	e := newEnv(t)
	if _, err := e.store.AddPasskey(t.Context(), passkeyFixture(e.admin.ID)); err != nil {
		t.Fatal(err)
	}
	resp, body := e.post(t, "/login", url.Values{"username": {"admin"}, "password": {"не тот"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("код %d, ожидался 401", resp.StatusCode)
	}
	if !strings.Contains(body, `id="pw-details" open`) {
		t.Fatal("после ошибки форма логина свёрнута")
	}
}

// Ключ привязан к имени панели: на localhost кнопка входа по ключу с публичного имени
// не показывается — такой ключ там всё равно не сработает.
func TestPasskeyButtonIsPerHost(t *testing.T) {
	e := newEnv(t)
	if _, err := e.store.AddPasskey(t.Context(), passkeyFixture(e.admin.ID)); err != nil {
		t.Fatal(err)
	}
	_, body := e.withHost(t, "panel.example.com", "/login")
	if !strings.Contains(body, "passkey-login") {
		t.Fatal("на своём имени кнопки входа по ключу нет")
	}
	_, body = e.withHost(t, "localhost", "/login")
	if strings.Contains(body, "passkey-login") {
		t.Fatal("на localhost показана кнопка для ключа с другого имени")
	}
	if !strings.Contains(body, `id="pw-details" open`) {
		t.Fatal("на localhost форма логина должна быть раскрыта")
	}
}
