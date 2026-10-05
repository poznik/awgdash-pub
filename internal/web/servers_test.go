package web

import (
	"net/http"
	"strings"
	"testing"

	"github.com/poznik/awgdash-pub/internal/store"
)

// Обзор показывает парк: сервер, под ним его интерфейсы, и связь по каждому.
func TestDashboardShowsPark(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	srv, err := e.store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.UpsertInterface(ctx, srv.ID, "awg-kz", store.InterfaceFacts{
		Subnet: "10.30.0.0/24", ListenPort: 443, MTU: 1280, IsAWG: true}); err != nil {
		t.Fatal(err)
	}
	e.login(t)

	// Обзор — про парк: карточка на каждый сервер с его интерфейсами (PLAN-UI §1.2).
	_, body := e.get(t, "/")
	// Флаг — рисунок из спрайта: эмодзи-флаги Windows не показывает вовсе.
	for _, want := range []string{"#flag-kz", "Казахстан", "/servers/kz", "awg-kz", "Кто грузит канал сейчас"} {
		if !strings.Contains(body, want) {
			t.Fatalf("на обзоре нет %q", want)
		}
	}
}

// Страница сервера открывается по слагу и показывает только его интерфейсы.
func TestServerPageBySlug(t *testing.T) {
	e := newEnv(t)
	ctx := t.Context()
	srv, err := e.store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.store.UpsertInterface(ctx, srv.ID, "awg-kz", store.InterfaceFacts{
		Subnet: "10.30.0.0/24", ListenPort: 443, MTU: 1280, IsAWG: true}); err != nil {
		t.Fatal(err)
	}
	e.login(t)

	resp, body := e.get(t, "/servers/kz")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("код %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "#flag-kz") || !strings.Contains(body, "Казахстан") || !strings.Contains(body, "awg-kz") {
		t.Fatal("страница сервера не про kz")
	}
	if strings.Contains(body, "awg-t0") {
		t.Fatal("на странице kz видны интерфейсы чужого сервера")
	}
	// У удалённого узла нет своей базы панели — размер не показываем.
	if strings.Contains(body, "База панели") {
		t.Fatal("у удалённого узла показан размер базы панели")
	}

	resp, _ = e.get(t, "/servers/нет-такого")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("несуществующий сервер отдал %d, ожидался 404", resp.StatusCode)
	}
}
