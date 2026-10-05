// Package auth — пароли (argon2id) и второй фактор (TOTP) для входа в админку (SPEC FR-13.1).
//
// Хеш хранится в переносимом виде `$argon2id$v=19$m=…,t=…,p=…$<соль>$<хеш>`: его можно проверить
// сторонним инструментом, а параметры поднять, не ломая старые записи.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"
)

// Параметры argon2id: 64 МБ и два прохода — заметно для перебора и незаметно для входа
// на одноядерном VPS (около 60 мс).
const (
	argonTime    = 2
	argonMemory  = 64 * 1024 // КиБ
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// MinPasswordLen — короче панель не принимает (пароль генерируется, а не придумывается).
const MinPasswordLen = 12

// HashPassword считает argon2id-хеш пароля со случайной солью.
func HashPassword(password string) (string, error) {
	// Длина — в символах: кириллический пароль из 8 букв занимает 16 байт, но короче он от этого не стал.
	if n := len([]rune(password)); n < MinPasswordLen {
		return "", fmt.Errorf("пароль короче %d символов (%d)", MinPasswordLen, n)
	}
	return hash(password)
}

// HashWeak хеширует пароль любой длины. Нужен для временного пароля, который оператор ставит
// осознанно и на короткий срок; в панели такой пароль поставить нельзя.
func HashWeak(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("пустой пароль")
	}
	return hash(password)
}

func hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// VerifyPassword сверяет пароль с хешем. Сравнение — постоянного времени.
func VerifyPassword(hash, password string) bool {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false
	}
	var memory uint32
	var times uint32
	var threads uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &times, &threads); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false
	}
	got := argon2.IDKey([]byte(password), salt, times, memory, threads, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// NewTOTP заводит секрет второго фактора и возвращает его вместе с otpauth-ссылкой для QR.
func NewTOTP(issuer, account string) (secret, uri string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1, // то, что понимают все приложения-аутентификаторы
	})
	if err != nil {
		return "", "", err
	}
	return key.Secret(), key.URL(), nil
}

// TOTPURI собирает otpauth-ссылку из уже сохранённого секрета: страница настроек рисует по ней QR.
func TOTPURI(issuer, account, secret string) string {
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", "6")
	v.Set("period", "30")
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode()
}

// VerifyTOTP проверяет шестизначный код. Допускается соседнее окно (±30 с) — часы на телефоне
// и на сервере расходятся, отказывать из-за этого нельзя.
func VerifyTOTP(secret, code string, now time.Time) bool {
	code = strings.TrimSpace(strings.ReplaceAll(code, " ", ""))
	if secret == "" || code == "" {
		return false
	}
	ok, err := totp.ValidateCustom(code, secret, now, totp.ValidateOpts{
		Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
	})
	return err == nil && ok
}

// NewPassword генерирует пароль из 20 символов без похожих начертаний: его читают с экрана.
func NewPassword() (string, error) {
	const alphabet = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, len(b))
	for i, v := range b {
		out[i] = alphabet[int(v)%len(alphabet)]
	}
	return string(out), nil
}
