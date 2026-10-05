package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/poznik/awgdash-pub/internal/awgtest"
)

func newTestAPI(t *testing.T, f *awgtest.Fake) (*httptest.Server, string) {
	t.Helper()
	n, path, _ := newTestNode(t, f)
	mux := http.NewServeMux()
	(&API{Node: n, Token: "секрет"}).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, path
}

func do(t *testing.T, srv *httptest.Server, method, path, token, body string) (*http.Response, string) {
	t.Helper()
	var r *http.Request
	var err error
	if body == "" {
		r, err = http.NewRequestWithContext(context.Background(), method, srv.URL+path, nil)
	} else {
		r, err = http.NewRequestWithContext(context.Background(), method, srv.URL+path, strings.NewReader(body))
	}
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := srv.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b := make([]byte, 64<<10)
	n, _ := resp.Body.Read(b)
	return resp, string(b[:n])
}

// Публичный ключ содержит + / = — в пути он приезжает закодированным.
func peerPath(iface, pub string) string {
	return "/v1/interfaces/" + iface + "/peers/" + url.PathEscape(pub)
}

func TestAPIRequiresToken(t *testing.T) {
	srv, _ := newTestAPI(t, awgtest.New())
	resp, _ := do(t, srv, "GET", "/v1/health", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("без токена: %d", resp.StatusCode)
	}
	resp, _ = do(t, srv, "PUT", peerPath("awg-t0", awgtest.KeyC), "чужой", `{"allowed_ips":["10.20.0.9/32"]}`)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("чужой токен: %d", resp.StatusCode)
	}
}

func TestAPIPutAndDeletePeer(t *testing.T) {
	f := awgtest.New()
	srv, path := newTestAPI(t, f)

	resp, body := do(t, srv, "PUT", peerPath("awg-t0", awgtest.KeyC), "секрет", `{"preshared_key":"`+awgtest.PSK+`","allowed_ips":["10.20.0.9/32"]}`)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT: %d %s", resp.StatusCode, body)
	}
	if p, ok := f.Peers[awgtest.KeyC]; !ok || !p.HasPSK || p.Allowed != "10.20.0.9/32" {
		t.Fatalf("рантайм: %+v", f.Peers)
	}
	conf, _ := os.ReadFile(path)
	if !strings.Contains(string(conf), awgtest.KeyC) {
		t.Fatal("пир не попал в файл")
	}

	resp, body = do(t, srv, "DELETE", peerPath("awg-t0", awgtest.KeyC), "секрет", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("DELETE: %d %s", resp.StatusCode, body)
	}
	if _, ok := f.Peers[awgtest.KeyC]; ok {
		t.Fatal("пир остался в рантайме")
	}
}

func TestAPIGuardReturns409(t *testing.T) {
	f := awgtest.New()
	f.Foreign = true
	srv, _ := newTestAPI(t, f)
	resp, body := do(t, srv, "PUT", peerPath("awg-t0", awgtest.KeyC), "секрет", `{"allowed_ips":["10.20.0.9/32"]}`)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("guard: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "wg-dashboard.service") {
		t.Fatalf("тело ответа: %s", body)
	}
}

func TestAPIReconcile(t *testing.T) {
	f := awgtest.New()
	srv, _ := newTestAPI(t, f)
	req := `{"peers":[
		{"public_key":"` + awgtest.KeyA + `","allowed_ips":["10.20.0.2/32"]},
		{"public_key":"` + awgtest.KeyC + `","allowed_ips":["10.20.0.9/32"],"preshared_key":"` + awgtest.PSK + `"}
	]}`
	resp, body := do(t, srv, "POST", "/v1/interfaces/awg-t0/reconcile", "секрет", req)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reconcile: %d %s", resp.StatusCode, body)
	}
	var res ReconcileResult
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		t.Fatalf("ответ не разобран: %v (%s)", err, body)
	}
	if len(res.Added) != 1 || res.Added[0] != awgtest.KeyC || len(res.Removed) != 1 || res.Removed[0] != awgtest.KeyB {
		t.Fatalf("результат: %+v", res)
	}
	// Пустой список без allow_empty — отказ.
	resp, body = do(t, srv, "POST", "/v1/interfaces/awg-t0/reconcile", "секрет", `{"peers":[]}`)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("пустой reconcile: %d %s", resp.StatusCode, body)
	}
}

func TestAPIReadEndpoints(t *testing.T) {
	f := awgtest.New()
	srv, _ := newTestAPI(t, f)
	for _, path := range []string{"/v1/health", "/v1/interfaces", "/v1/interfaces/awg-t0/dump", "/v1/interfaces/awg-t0/conf-peers"} {
		resp, body := do(t, srv, "GET", path, "секрет", "")
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, body)
		}
	}
	resp, body := do(t, srv, "POST", "/v1/interfaces/awg-t0/verify", "секрет", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("verify: %d %s", resp.StatusCode, body)
	}
}

// Имя интерфейса из пути запроса не должно уводить чтение за каталог конфигов.
func TestConfRejectsPathTraversal(t *testing.T) {
	n, _, _ := newTestNode(t, awgtest.New())
	for _, bad := range []string{"../etc/passwd", "..", "awg/../../x", "awg de", ""} {
		if _, err := n.ConfRaw(bad); err == nil {
			t.Fatalf("имя %q принято", bad)
		}
	}
	if _, err := n.ConfRaw("awg-t0"); err != nil {
		t.Fatalf("нормальное имя отвергнуто: %v", err)
	}
}

// Ручка конфига отдаёт файл как есть — копиям нужен именно он, а не разбор.
func TestAPIConfReturnsFile(t *testing.T) {
	srv, _ := newTestAPI(t, awgtest.New())
	resp, body := do(t, srv, http.MethodGet, "/v1/interfaces/awg-t0/conf", "секрет", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("код %d: %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "[Interface]") {
		t.Fatalf("это не конфиг: %q", body)
	}
	// Без токена — отказ.
	resp, _ = do(t, srv, http.MethodGet, "/v1/interfaces/awg-t0/conf", "", "")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("без токена код %d, ожидался 401", resp.StatusCode)
	}
}
