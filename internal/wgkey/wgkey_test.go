package wgkey

import (
	"encoding/base64"
	"testing"
)

func TestGenerateAndDerive(t *testing.T) {
	p, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if !Valid(p.Private) || !Valid(p.Public) {
		t.Fatalf("ключи не проходят проверку: %+v", p)
	}
	if p.Private == p.Public {
		t.Fatal("приватный и публичный совпали")
	}
	got, err := Public(p.Private)
	if err != nil {
		t.Fatal(err)
	}
	if got != p.Public {
		t.Fatalf("Public(private) = %s, ожидалось %s", got, p.Public)
	}
}

// Вектор сверен с `awg pubkey` (amneziawg-tools v3.0.20260805): панель обязана давать тот же ключ.
func TestKnownVector(t *testing.T) {
	const priv = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
	const want = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw="
	got, err := Public(priv)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("Public = %s, ожидалось %s", got, want)
	}
}

func TestClampIdempotent(t *testing.T) {
	// Ключ без clamp даёт тот же публичный, что и после clamp: awg делает clamp сам.
	raw := make([]byte, KeyLen)
	for i := range raw {
		raw[i] = byte(i * 7)
	}
	s := base64.StdEncoding.EncodeToString(raw)
	a, err := Public(s)
	if err != nil {
		t.Fatal(err)
	}
	var k [KeyLen]byte
	copy(k[:], raw)
	clamp(&k)
	b, err := Public(base64.StdEncoding.EncodeToString(k[:]))
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatalf("clamp меняет результат: %s vs %s", a, b)
	}
}

func TestPSKUnique(t *testing.T) {
	a, err := PSK()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := PSK()
	if a == b {
		t.Fatal("два PSK совпали")
	}
	if !Valid(a) {
		t.Fatalf("PSK не проходит проверку: %s", a)
	}
}

func TestDecodeErrors(t *testing.T) {
	for _, s := range []string{"", "не base64!", "c2hvcnQ=", "AAAA"} {
		if Valid(s) {
			t.Fatalf("%q принят за ключ", s)
		}
	}
}
