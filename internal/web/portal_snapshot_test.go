//go:build devserver

// Снимок портала для осмотра глазами: страница портала самодостаточна (стили встроены, шрифты
// системные), поэтому её тело можно открыть файлом в любом браузере и посмотреть на телефонной
// ширине. Стенд для этого не годится: портал живёт на отдельном имени, а localhost — админкино.
// Запуск: AWGDASH_SNAPSHOT_DIR=<каталог> go test ./internal/web -tags devserver -run TestPortalSnapshot
package web

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/store"
)

func TestPortalSnapshot(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()

	// Парк как живой: четыре сервера под управлением — на них и проверяется, что выбор
	// умещается в телефонный экран.
	park := []struct{ slug, title, country, iface, subnet string }{
		{"kz", "Казахстан", "KZ", "awg-kz", "10.30.0.0/24"},
		{"hel", "Финляндия", "FI", "awg-hel", "10.8.0.0/24"},
		{"ru", "Россия (хаб)", "RU", "awg-ru", "10.40.0.0/23"},
	}
	for i, p := range park {
		srv, err := e.store.AddServer(ctx, store.NewServer{Slug: p.slug, Title: p.title, NodePort: 10089 + i, Country: p.country})
		if err != nil {
			t.Fatal(err)
		}
		id, err := e.store.UpsertInterface(ctx, srv.ID, p.iface, store.InterfaceFacts{
			Subnet: p.subnet, ServerAddress: "10.30.0.1/24", ListenPort: 443, MTU: 1280, IsAWG: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := e.store.SetInterfaceMode(ctx, id, hub.ModeOwn); err != nil {
			t.Fatal(err)
		}
	}

	uid, token, err := e.store.CreateUser(ctx, store.User{Name: "Мария", SelfService: true, MaxDevices: 5})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"iPhone 16 PM RU", "MBA RU"} {
		if _, err := e.hub.CreateDevice(ctx, hub.NewDevice{UserID: uid, InterfaceID: e.iface.ID, Name: name,
			Preset: store.PresetPhone, CreatedBy: "admin", Actor: store.ActorAdmin}); err != nil {
			t.Fatal(err)
		}
	}

	_, body := e.withHost(t, "portal.example.com", "/u/"+token)
	dir := os.Getenv("AWGDASH_SNAPSHOT_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	path := filepath.Join(dir, "portal.html")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	fmt.Printf("\n>>> снимок портала: %s (%d КБ)\n\n", path, len(body)/1024)
}
