package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"filippo.io/age"
)

func makeFile(t *testing.T, dir, name, body string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func testManifest() Manifest {
	return Manifest{Kind: KindConfig, CreatedAt: time.Now(), Version: "тест", AWGVersion: "awg v3",
		Server:     Server{Slug: "de", Hostname: "node.example.com", EgressIface: "eth0"},
		Interfaces: []Iface{{Name: "awg-de", ConfPath: "/etc/amnezia/amneziawg/awg-de.conf", ListenPort: 443, MTU: 1280, Mode: "own", Peers: 5}}}
}

// Копия разворачивается обратно тем же содержимым — это главное свойство бэкапа.
func TestCreateAndOpenRoundTrip(t *testing.T) {
	dir := t.TempDir()
	secret, public, err := Keygen()
	if err != nil {
		t.Fatal(err)
	}
	db := makeFile(t, dir, "src/db.sqlite", "SQLite format 3\x00данные панели")
	conf := makeFile(t, dir, "src/awg-de.conf", "[Interface]\nPrivateKey = ключ\nJc = 6\n")
	dst := filepath.Join(dir, Name(KindConfig, time.Now()))

	size, err := Create(dst, public, testManifest(), []Entry{
		{Name: "db.sqlite", Path: db},
		{Name: "conf/awg-de.conf", Path: conf},
	})
	if err != nil {
		t.Fatal(err)
	}
	if size < 100 {
		t.Fatalf("подозрительно маленький архив: %d байт", size)
	}
	// Зашифрованный файл не должен содержать ни ключей, ни узнаваемых строк.
	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	for _, secretish := range []string{"PrivateKey", "ключ", "awg-de"} {
		if strings.Contains(string(raw), secretish) {
			t.Fatalf("в зашифрованном файле видно %q", secretish)
		}
	}

	ids, err := age.ParseIdentities(strings.NewReader(secret))
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	m, err := Open(dst, ids, out)
	if err != nil {
		t.Fatal(err)
	}
	if m.Server.Slug != "de" || len(m.Interfaces) != 1 || m.Interfaces[0].Peers != 5 {
		t.Fatalf("манифест приехал не тот: %+v", m)
	}
	if len(m.Files) != 2 {
		t.Fatalf("в манифесте %d файлов, ожидалось 2", len(m.Files))
	}
	got, err := os.ReadFile(filepath.Join(out, "conf", "awg-de.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "[Interface]\nPrivateKey = ключ\nJc = 6\n" {
		t.Fatalf("конфиг восстановлен неверно: %q", got)
	}
}

// Чужим ключом копия не открывается.
func TestOpenWithWrongKey(t *testing.T) {
	dir := t.TempDir()
	_, public, _ := Keygen()
	otherSecret, _, _ := Keygen()
	db := makeFile(t, dir, "src/db.sqlite", "данные")
	dst := filepath.Join(dir, "copy.age")
	if _, err := Create(dst, public, testManifest(), []Entry{{Name: "db.sqlite", Path: db}}); err != nil {
		t.Fatal(err)
	}
	ids, _ := age.ParseIdentities(strings.NewReader(otherSecret))
	if _, err := Open(dst, ids, ""); err == nil {
		t.Fatal("копия открылась чужим ключом")
	}
}

// Порча файла ловится: age не расшифрует изменённый поток.
func TestOpenDetectsCorruption(t *testing.T) {
	dir := t.TempDir()
	secret, public, _ := Keygen()
	db := makeFile(t, dir, "src/db.sqlite", strings.Repeat("данные панели ", 200))
	dst := filepath.Join(dir, "copy.age")
	if _, err := Create(dst, public, testManifest(), []Entry{{Name: "db.sqlite", Path: db}}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-20] ^= 0xff
	if err := os.WriteFile(dst, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	ids, _ := age.ParseIdentities(strings.NewReader(secret))
	if _, err := Open(dst, ids, ""); err == nil {
		t.Fatal("испорченная копия прочиталась без ошибки")
	}
}

// Без получателя копия не создаётся: незашифрованных копий с ключами быть не должно.
func TestCreateRequiresRecipient(t *testing.T) {
	dir := t.TempDir()
	db := makeFile(t, dir, "src/db.sqlite", "данные")
	if _, err := Create(filepath.Join(dir, "copy.age"), "  ", testManifest(), []Entry{{Name: "db.sqlite", Path: db}}); err != ErrNoRecipient {
		t.Fatalf("ожидалась ErrNoRecipient, получено %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "copy.age")); !os.IsNotExist(err) {
		t.Fatal("файл создан, хотя шифровать было нечем")
	}
}

// Имя копии читаемо и отражает вид и время.
func TestName(t *testing.T) {
	at := time.Date(2026, 8, 24, 3, 30, 0, 0, time.UTC)
	if got := Name(KindConfig, at); got != "awgdash-config-20260824-0330.tar.zst.age" {
		t.Fatalf("имя копии: %q", got)
	}
	if got := Name(KindFull, at); !strings.HasPrefix(got, "awgdash-full-") {
		t.Fatalf("имя полной копии: %q", got)
	}
}

// Ключ читается из файла, где рядом лежат комментарии и публичный ключ: именно так выглядит
// сохранённый вывод keygen.
func TestIdentitiesIgnoresNoise(t *testing.T) {
	dir := t.TempDir()
	secret, public, err := Keygen()
	if err != nil {
		t.Fatal(err)
	}
	body := "# приватный ключ — в менеджер паролей\n" + secret + "\n\n# публичный ключ\nAWGDASH_AGE_RECIPIENT=" + public + "\n"
	path := makeFile(t, dir, "key.txt", body)
	ids, err := Identities(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("прочитано ключей: %d", len(ids))
	}
	// Файл без приватного ключа даёт понятную ошибку, а не «no identities found».
	only := makeFile(t, dir, "pub.txt", "AWGDASH_AGE_RECIPIENT="+public+"\n")
	if _, err := Identities(only); err == nil || !strings.Contains(err.Error(), "AGE-SECRET-KEY-1") {
		t.Fatalf("ошибка о недостающем ключе: %v", err)
	}
}
