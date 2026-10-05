package nodeclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/poznik/awgdash-pub/internal/awg"
	"github.com/poznik/awgdash-pub/internal/awgtest"
	"github.com/poznik/awgdash-pub/internal/node"
)

// Клиент проверяется против настоящего API узла: контракт один, и разъезд между сторонами
// должен ломать тест, а не работу на живом сервере.
func testPair(t *testing.T) (*Client, *awgtest.Fake) {
	t.Helper()
	dir := t.TempDir()
	confDir := filepath.Join(dir, "etc")
	if _, err := awgtest.WriteConf(confDir, "awg-t0"); err != nil {
		t.Fatal(err)
	}
	f := awgtest.New()
	// Один пир с рукопожатием: иначе не видно, что время приезжает временем, а не нулём.
	withHS := f.Peers[awgtest.KeyA]
	withHS.Handshake = time.Now().Add(-time.Minute).Unix()
	f.Peers[awgtest.KeyA] = withHS
	n := node.New(confDir, "awg", f, []string{"wg-dashboard.service"})
	n.BackupDir = filepath.Join(dir, "conf-backup")
	mux := http.NewServeMux()
	(&node.API{Node: n, Token: "секрет"}).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := New(srv.URL, "секрет")
	c.HTTP = srv.Client()
	return c, f
}

func TestHealthAndCompatibility(t *testing.T) {
	c, _ := testPair(t)
	ctx := context.Background()
	h, err := c.CheckCompatible(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if h.AWGVersion == "" || len(h.Interfaces) != 1 || h.Interfaces[0] != "awg-t0" {
		t.Fatalf("здоровье узла: %+v", h)
	}
	// Чужой токен — отказ, а не молчаливая работа.
	bad := New(c.Base, "не тот")
	bad.HTTP = c.HTTP
	if _, err := bad.Health(ctx); err == nil {
		t.Fatal("узел ответил на чужой токен")
	} else if e, ok := err.(*Error); !ok || e.Code != http.StatusUnauthorized {
		t.Fatalf("ожидался 401, получено %v", err)
	}
}

func TestDiscoverDumpAndConf(t *testing.T) {
	c, _ := testPair(t)
	ctx := context.Background()
	ifaces, err := c.Discover(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(ifaces) != 1 || ifaces[0].Name != "awg-t0" {
		t.Fatalf("интерфейсы: %+v", ifaces)
	}
	if ifaces[0].ListenPort == 0 || ifaces[0].MTU == 0 {
		t.Fatalf("параметры интерфейса не приехали: %+v", ifaces[0])
	}

	id, peers, err := c.Dump(ctx, "awg-t0")
	if err != nil {
		t.Fatal(err)
	}
	if id.PublicKey == "" || !id.IsAWG || len(id.Obf) == 0 {
		t.Fatalf("дамп интерфейса: %+v", id)
	}
	if len(peers) == 0 {
		t.Fatal("в дампе нет пиров")
	}
	// Время хендшейка должно приехать временем, а не нулём.
	var withHandshake int
	for _, p := range peers {
		if !p.LatestHandshake.IsZero() {
			withHandshake++
		}
	}
	if withHandshake == 0 {
		t.Fatal("ни у одного пира не разобралось время хендшейка")
	}

	confPeers, err := c.ConfPeers(ctx, "awg-t0")
	if err != nil {
		t.Fatal(err)
	}
	if len(confPeers) == 0 {
		t.Fatal("пиры файла не приехали")
	}
	raw, err := c.ConfRaw(ctx, "awg-t0")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "[Interface]") {
		t.Fatalf("конфиг не похож на конфиг: %q", string(raw[:40]))
	}

	res, err := c.Verify(ctx, "awg-t0")
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("обфускация разошлась: %+v", res.Diffs)
	}
}

func TestWriteThroughClient(t *testing.T) {
	c, f := testPair(t)
	ctx := context.Background()
	spec := awg.PeerSpec{PublicKey: awgtest.KeyC, PresharedKey: awgtest.PSK, AllowedIPs: []string{"10.20.0.42/32"}}
	if err := c.ApplyPeer(ctx, "awg-t0", spec); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Peers[spec.PublicKey]; !ok {
		t.Fatal("пир не появился в рантайме")
	}
	raw, _ := c.ConfRaw(ctx, "awg-t0")
	if !strings.Contains(string(raw), spec.PublicKey) {
		t.Fatal("пир не появился в файле")
	}

	if err := c.RemovePeer(ctx, "awg-t0", spec.PublicKey); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Peers[spec.PublicKey]; ok {
		t.Fatal("пир остался в рантайме после удаления")
	}
}

// Примерка reconcile ничего не меняет — этим она и полезна администратору.
func TestPlanReconcileDoesNotWrite(t *testing.T) {
	c, f := testPair(t)
	ctx := context.Background()
	before, _ := c.ConfRaw(ctx, "awg-t0")
	desired := []awg.PeerSpec{{PublicKey: awgtest.KeyC, AllowedIPs: []string{"10.20.0.42/32"}}}

	plan, err := c.PlanReconcile(ctx, "awg-t0", desired, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Added) != 1 || plan.Added[0] != awgtest.KeyC {
		t.Fatalf("примерка обещала добавить %v, ожидался один новый пир", plan.Added)
	}
	if _, ok := f.Peers[awgtest.KeyC]; ok {
		t.Fatal("примерка изменила рантайм")
	}
	after, _ := c.ConfRaw(ctx, "awg-t0")
	if string(before) != string(after) {
		t.Fatal("примерка изменила файл")
	}

	res, err := c.Reconcile(ctx, "awg-t0", desired, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Peers[awgtest.KeyC]; len(res.Added) != 1 || !ok {
		t.Fatalf("настоящий reconcile не сработал: %+v", res)
	}
}

// Недоступный узел даёт внятную ошибку, а не панику: связь по туннелю рвётся регулярно.
func TestUnreachableNode(t *testing.T) {
	c := New("http://127.0.0.1:1", "секрет")
	if _, err := c.Health(context.Background()); err == nil {
		t.Fatal("недоступный узел ответил")
	} else if !strings.Contains(err.Error(), "недоступен") {
		t.Fatalf("невнятная ошибка: %v", err)
	}
}

// Клиент забирает накопленные узлом выборки: именно так хаб добирает пропущенное,
// когда туннель до узла был порван.
func TestSamplesThroughClient(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "etc")
	if _, err := awgtest.WriteConf(confDir, "awg-t0"); err != nil {
		t.Fatal(err)
	}
	n := node.New(confDir, "awg", awgtest.New(), nil)
	buf := node.NewBuffer()
	ctx := context.Background()
	if err := n.Sample(ctx, buf); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	(&node.API{Node: n, Token: "секрет", Samples: buf}).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := New(srv.URL, "секрет")
	c.HTTP = srv.Client()

	got, err := c.Samples(ctx, time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Interface != "awg-t0" || len(got[0].Peers) == 0 {
		t.Fatalf("выборки не приехали: %+v", got)
	}
	if got[0].At.IsZero() {
		t.Fatal("у выборки нет времени — хаб не сможет положить её в историю")
	}
	// Всё, что старше отсечки, не приезжает.
	empty, err := c.Samples(ctx, time.Now().Add(time.Minute), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(empty) != 0 {
		t.Fatalf("since не сработал: %d выборок", len(empty))
	}
}

// Ответ узла крупнее прежнего потолка в 8 МБ обязан читаться целиком. На живом парке узел
// накопил суточный буфер выборок, ответ на 12 МБ обрезался посреди JSON, и панель переставала
// видеть, кто в туннеле, — при работающем туннеле.
func TestLargeResponseIsReadWhole(t *testing.T) {
	// Одна выборка с сотней пиров, повторённая столько раз, чтобы тело перевалило 8 МБ.
	peers := make([]awg.PeerDump, 0, 100)
	for i := 0; i < 100; i++ {
		peers = append(peers, awg.PeerDump{
			PublicKey:  fmt.Sprintf("%043d=", i),
			AllowedIPs: []string{fmt.Sprintf("10.8.%d.%d/32", i/250, i%250)},
			Endpoint:   "203.0.113.7:51820",
		})
	}
	var buf []node.Sample
	at := time.Now().Add(-24 * time.Hour)
	for i := 0; len(buf) == 0 || i < 900; i++ {
		buf = append(buf, node.Sample{At: at.Add(time.Duration(i) * time.Second), Interface: "awg-t0", Peers: peers})
	}
	body, err := json.Marshal(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) <= 8<<20 {
		t.Fatalf("тело %d байт — тест не проверяет прежний потолок", len(body))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/samples", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(body)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	c := New(srv.URL, "")
	c.HTTP = srv.Client()

	got, err := c.Samples(context.Background(), time.Time{}, 0)
	if err != nil {
		t.Fatalf("ответ %d байт не прочитан: %v", len(body), err)
	}
	if len(got) != len(buf) {
		t.Fatalf("выборок пришло %d из %d", len(got), len(buf))
	}
}
