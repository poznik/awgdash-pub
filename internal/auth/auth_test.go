package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestPasswordRoundTrip(t *testing.T) {
	const pw = "правильный-пароль-1"
	hash, err := HashPassword(pw)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(hash, "$argon2id$v=19$m=65536,t=2,p=4$") {
		t.Fatalf("формат хеша: %s", hash)
	}
	if strings.Contains(hash, pw) {
		t.Fatal("пароль виден в хеше")
	}
	if !VerifyPassword(hash, pw) {
		t.Fatal("верный пароль не принят")
	}
	if VerifyPassword(hash, pw+" ") || VerifyPassword(hash, "другой-пароль-12") {
		t.Fatal("принят неверный пароль")
	}
	// Соль случайна: два хеша одного пароля различаются.
	hash2, _ := HashPassword(pw)
	if hash == hash2 {
		t.Fatal("соль не случайна")
	}
	if VerifyPassword("мусор", pw) || VerifyPassword("", pw) || VerifyPassword("$argon2id$v=19$m=x$s$h", pw) {
		t.Fatal("испорченный хеш принят")
	}
}

func TestPasswordLength(t *testing.T) {
	if _, err := HashPassword("короткий"); err == nil {
		t.Fatal("принят короткий пароль")
	}
	// HashWeak — для временного пароля по явной команде оператора: длина не проверяется,
	// но пустой пароль не принимается и здесь.
	weak, err := HashWeak("admin")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword(weak, "admin") || VerifyPassword(weak, "admin2") {
		t.Fatal("слабый пароль проверяется неверно")
	}
	if _, err := HashWeak(""); err == nil {
		t.Fatal("принят пустой пароль")
	}
	pw, err := NewPassword()
	if err != nil {
		t.Fatal(err)
	}
	if len(pw) != 20 {
		t.Fatalf("длина сгенерированного пароля: %d", len(pw))
	}
	if strings.ContainsAny(pw, "0OlI1") {
		t.Fatalf("в пароле похожие символы: %s", pw)
	}
	if _, err := HashPassword(pw); err != nil {
		t.Fatal(err)
	}
}

func TestTOTP(t *testing.T) {
	secret, uri, err := NewTOTP("awgdash", "admin")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(uri, "otpauth://totp/awgdash:admin") || !strings.Contains(uri, "secret=") {
		t.Fatalf("otpauth-ссылка: %s", uri)
	}
	now := time.Now()
	code, err := totp.GenerateCode(secret, now)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyTOTP(secret, code, now) {
		t.Fatal("свой же код не принят")
	}
	// Пробелы в коде — обычное дело при копировании из приложения.
	if !VerifyTOTP(secret, " "+code[:3]+" "+code[3:]+" ", now) {
		t.Fatal("код с пробелами не принят")
	}
	// Соседнее окно принимается, дальнее — нет.
	if !VerifyTOTP(secret, code, now.Add(-25*time.Second)) {
		t.Fatal("код соседнего окна отвергнут")
	}
	if VerifyTOTP(secret, code, now.Add(5*time.Minute)) {
		t.Fatal("принят просроченный код")
	}
	if VerifyTOTP(secret, "000000", now) && VerifyTOTP(secret, "", now) {
		t.Fatal("принят пустой или нулевой код")
	}
	if VerifyTOTP("", code, now) {
		t.Fatal("принят код без секрета")
	}
}
