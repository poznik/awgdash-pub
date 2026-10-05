package node

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/poznik/awgdash-pub/internal/awg"
	"github.com/poznik/awgdash-pub/internal/awgtest"
)

// Буфер отдаёт только то, что новее указанного момента, и не растёт бесконечно.
func TestBufferWindowAndSince(t *testing.T) {
	b := NewBuffer()
	base := time.Now().Add(-48 * time.Hour)
	for i := 0; i < 10; i++ {
		b.Add(Sample{At: base.Add(time.Duration(i) * time.Hour), Interface: "awg-t0"})
	}
	// Всё это старше суток — при добавлении свежей выборки старое должно уйти.
	b.Add(Sample{At: time.Now(), Interface: "awg-t0"})
	if n := b.Len(); n != 1 {
		t.Fatalf("в буфере %d выборок, ожидалась одна свежая", n)
	}

	b = NewBuffer()
	now := time.Now()
	for i := 0; i < 5; i++ {
		b.Add(Sample{At: now.Add(time.Duration(i) * time.Second), Interface: "awg-t0"})
	}
	got := b.Since(now.Add(2*time.Second), 0)
	if len(got) != 2 {
		t.Fatalf("после отсечки осталось %d выборок, ожидалось 2", len(got))
	}
	if !got[0].At.After(now.Add(2 * time.Second)) {
		t.Fatal("в выборку попало то, что старше отсечки")
	}
	if all := b.Since(time.Time{}, 0); len(all) != 5 {
		t.Fatalf("без отсечки отдано %d выборок, ожидалось 5", len(all))
	}
	if lim := b.Since(time.Time{}, 2); len(lim) != 2 || !lim[1].At.Equal(now.Add(4*time.Second)) {
		t.Fatalf("лимит отдал не самые свежие: %+v", lim)
	}
}

// Число выборок ограничено и по количеству: сутки при частом опросе не должны съесть память.
func TestBufferMaxItems(t *testing.T) {
	b := &Buffer{window: SampleWindow, max: 3}
	now := time.Now()
	for i := 0; i < 10; i++ {
		b.Add(Sample{At: now.Add(time.Duration(i) * time.Second), Interface: "awg-t0"})
	}
	if b.Len() != 3 {
		t.Fatalf("в буфере %d выборок, ожидалось 3", b.Len())
	}
	if got := b.Since(time.Time{}, 0); !got[0].At.Equal(now.Add(7 * time.Second)) {
		t.Fatalf("обрезаны не старые записи: первая %v", got[0].At)
	}
}

// Выборка узла кладёт в буфер и пиров рантайма, и ключи из файла конфига.
func TestNodeSampleFillsBuffer(t *testing.T) {
	n, _, _ := newTestNode(t, awgtest.New())
	buf := NewBuffer()
	if err := n.Sample(context.Background(), buf); err != nil {
		t.Fatal(err)
	}
	got := buf.Since(time.Time{}, 0)
	if len(got) != 1 || got[0].Interface != "awg-t0" {
		t.Fatalf("буфер: %+v", got)
	}
	if len(got[0].Peers) == 0 {
		t.Fatal("в выборке нет пиров")
	}
	if len(got[0].InConf) == 0 {
		t.Fatal("в выборке нет ключей из файла конфига")
	}
}

// Ручка /v1/samples отдаёт накопленное и понимает since.
func TestAPISamples(t *testing.T) {
	f := awgtest.New()
	n, _, _ := newTestNode(t, f)
	buf := NewBuffer()
	old := time.Now().Add(-time.Hour)
	buf.Add(Sample{At: old, Interface: "awg-t0", Peers: []awg.PeerDump{{PublicKey: awgtest.KeyA}}})
	buf.Add(Sample{At: time.Now(), Interface: "awg-t0", Peers: []awg.PeerDump{{PublicKey: awgtest.KeyB}}})

	mux := http.NewServeMux()
	(&API{Node: n, Token: "секрет", Samples: buf}).Register(mux)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	resp, body := do(t, srv, http.MethodGet, "/v1/samples", "секрет", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("код %d: %s", resp.StatusCode, body)
	}
	var all []Sample
	if err := json.Unmarshal([]byte(body), &all); err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Fatalf("отдано %d выборок, ожидалось 2", len(all))
	}
	_, body = do(t, srv, http.MethodGet, "/v1/samples?since="+strconv.FormatInt(old.Add(time.Minute).Unix(), 10), "секрет", "")
	var fresh []Sample
	json.Unmarshal([]byte(body), &fresh)
	if len(fresh) != 1 || fresh[0].Peers[0].PublicKey != awgtest.KeyB {
		t.Fatalf("since отдал не то: %+v", fresh)
	}
	// Здоровье узла показывает, сколько он держит для хаба.
	_, body = do(t, srv, http.MethodGet, "/v1/health", "секрет", "")
	var h Health
	json.Unmarshal([]byte(body), &h)
	if h.Buffered != 2 {
		t.Fatalf("в health буфер = %d, ожидалось 2", h.Buffered)
	}
}
