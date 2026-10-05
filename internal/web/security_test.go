package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// badLogin шлёт попытку входа с неверным паролем; xff — что клиент прислал в X-Forwarded-For.
func badLogin(t *testing.T, e *testEnv, xff, username string) (int, string) {
	t.Helper()
	form := url.Values{"username": {username}, "password": {"заведомо-неверный"}}
	req, _ := http.NewRequest("POST", e.srv.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}
	resp, body := e.do(t, req)
	return resp.StatusCode, body
}

// Подделанное начало цепочки X-Forwarded-For не должно сбрасывать счётчик попыток: адрес
// клиента приносит обратный прокси в хвосте цепочки (FR-13.1b). До правки перебор с новым
// значением заголовка на каждый запрос шёл бесконечно.
func TestForwardedForDoesNotResetLoginLimiter(t *testing.T) {
	e := newEnv(t)
	blockedAt := 0
	for i := 1; i <= 12 && blockedAt == 0; i++ {
		// Клиент называет себя разными адресами; прокси дописывает настоящий в конец.
		_, body := badLogin(t, e, "203.0.113."+strconv.Itoa(i)+", 198.51.100.7", "admin")
		if strings.Contains(body, "слишком много попыток") {
			blockedAt = i
		}
	}
	if blockedAt == 0 {
		t.Fatal("двенадцать попыток подряд с подделанным X-Forwarded-For не встретили ограничителя")
	}
	if blockedAt > 6 {
		t.Fatalf("ограничитель сработал только на %d-й попытке", blockedAt)
	}
}

// Разные настоящие адреса (последний элемент цепочки) считаются по отдельности: сосед по NAT
// не должен закрывать вход всем остальным.
func TestLimiterCountsProxyAddress(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 6; i++ {
		badLogin(t, e, "198.51.100.7", "admin")
	}
	if _, body := badLogin(t, e, "198.51.100.7", "admin"); !strings.Contains(body, "слишком много попыток") {
		t.Fatal("свой адрес не заблокирован после шести неудач")
	}
	if _, body := badLogin(t, e, "198.51.100.9", "admin"); strings.Contains(body, "слишком много попыток") {
		t.Fatal("чужой адрес заблокирован вместе с соседним")
	}
}

// Пока обе проверки пароля заняты, панель отвечает 429 вместо того, чтобы занимать под argon2id
// ещё 64 МиБ (FR-13.1d).
func TestPasswordChecksAreLimited(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < maxPasswordChecks; i++ {
		if !e.web.holdPasswordSlot() {
			t.Fatalf("место %d в очереди занять не удалось", i+1)
		}
	}
	defer func() {
		for i := 0; i < maxPasswordChecks; i++ {
			e.web.releasePasswordSlot()
		}
	}()
	code, body := badLogin(t, e, "198.51.100.7", "admin")
	if code != http.StatusTooManyRequests {
		t.Fatalf("вход при занятой очереди ответил %d, ожидался 429", code)
	}
	if !strings.Contains(body, "панель занята") {
		t.Fatalf("ответ не объясняет отказ: %s", body)
	}
}

// Присланное имя пользователя не должно раздувать журнал: в аудит уходит обрезанное значение
// (FR-12.1a). До правки одна попытка входа клала в БД столько, сколько прислал клиент.
func TestLongUsernameDoesNotBloatAudit(t *testing.T) {
	e := newEnv(t)
	// 5000 кириллических символов — это 45 КБ в URL-кодировке: тело проходит по лимиту,
	// и запись в журнале появляется. Всё, что крупнее, отбивается ещё на чтении формы.
	badLogin(t, e, "198.51.100.7", strings.Repeat("Ы", 5000))
	var n, size int
	err := e.store.DB().QueryRow(`SELECT COUNT(*), COALESCE(MAX(LENGTH(details)),0) FROM audit_log WHERE action = 'admin.login_failed'`).Scan(&n, &size)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("записей о неудачном входе: %d, ожидалась одна", n)
	}
	if size > 1024 {
		t.Fatalf("детали записи заняли %d байт", size)
	}
}

// Тело формы входа ограничено (FR-13.1d): мегабайты в поле пароля панель не разбирает.
func TestLoginBodyIsLimited(t *testing.T) {
	e := newEnv(t)
	form := url.Values{"username": {"admin"}, "password": {strings.Repeat("x", maxLoginBody+1024)}}
	req, _ := http.NewRequest("POST", e.srv.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, _ := e.do(t, req)
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusSeeOther {
		t.Fatalf("переросшая форма принята: %d", resp.StatusCode)
	}
}

// safeNext не выпускает редирект за пределы панели (находка №6): фишинг-ссылка «наша»,
// а после входа браузер уходит на копию панели.
func TestSafeNextRejectsOffsite(t *testing.T) {
	offsite := []string{
		`/\evil.example.com`, `//evil.example.com`, `/%2f%2fevil.example.com`,
		`/%5cevil.example.com`, `https://evil.example.com`, `https:/evil`, `javascript:alert(1)`,
	}
	for _, n := range offsite {
		if got := safeNext(n); strings.HasPrefix(got, "http") || got == n && got != "/" {
			t.Errorf("safeNext(%q) = %q — выпустило наружу", n, got)
		}
		if got := safeNext(n); got != "/" {
			t.Errorf("safeNext(%q) = %q, ожидалось /", n, got)
		}
	}
	// свой путь сохраняется целиком
	for _, n := range []string{"/users/42", "/settings?tab=keys", "/"} {
		if got := safeNext(n); got != n {
			t.Errorf("safeNext(%q) = %q — свой путь искажён", n, got)
		}
	}
}
