// Package wgkey — ключи WireGuard/AmneziaWG: пара curve25519, preshared-ключ, проверка формата.
//
// Ключи генерируются только на хабе (SPEC §9): узел приватных ключей клиентов не видит.
package wgkey

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"golang.org/x/crypto/curve25519"
)

// KeyLen — длина ключа в байтах; в текстовом виде это 44 символа стандартного base64.
const KeyLen = 32

// Pair — пара ключей устройства в текстовом виде (base64, как в конфигах awg).
type Pair struct {
	Private string
	Public  string
}

// Generate создаёт новую пару ключей.
func Generate() (Pair, error) {
	var priv [KeyLen]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return Pair{}, err
	}
	clamp(&priv)
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return Pair{}, err
	}
	return Pair{Private: encode(priv[:]), Public: encode(pub)}, nil
}

// Public выводит публичный ключ из приватного (для импорта чужих устройств).
func Public(private string) (string, error) {
	b, err := Decode(private)
	if err != nil {
		return "", err
	}
	var priv [KeyLen]byte
	copy(priv[:], b)
	clamp(&priv)
	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return "", err
	}
	return encode(pub), nil
}

// PSK создаёт preshared-ключ (32 случайных байта).
func PSK() (string, error) {
	var k [KeyLen]byte
	if _, err := rand.Read(k[:]); err != nil {
		return "", err
	}
	return encode(k[:]), nil
}

// Decode разбирает ключ из base64 и проверяет длину.
func Decode(s string) ([]byte, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("ключ не в base64: %w", err)
	}
	if len(b) != KeyLen {
		return nil, fmt.Errorf("длина ключа %d байт, ожидается %d", len(b), KeyLen)
	}
	return b, nil
}

// Valid — true, если строка похожа на ключ WireGuard.
func Valid(s string) bool {
	_, err := Decode(s)
	return err == nil
}

// clamp приводит приватный ключ к виду, который требует curve25519 (как `wg genkey`).
func clamp(k *[KeyLen]byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

func encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
