package node

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/awg"
	"github.com/poznik/awgdash-pub/internal/version"
)

// API — HTTP-контракт узла (SPEC §9), только loopback, bearer-токен.
type API struct {
	Node  *Node
	Token string
	// Samples — буфер выборок узла (FR-10.4). Пустой у хаба: он опрашивает свой узел сам.
	Samples *Buffer
}

// Register вешает маршруты /v1/* на mux.
func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/health", a.auth(a.health))
	mux.HandleFunc("GET /v1/host", a.auth(a.host))
	mux.HandleFunc("GET /v1/host/metrics", a.auth(a.metrics))
	mux.HandleFunc("GET /v1/interfaces", a.auth(a.interfaces))
	mux.HandleFunc("GET /v1/interfaces/{iface}/dump", a.auth(a.dump))
	mux.HandleFunc("GET /v1/interfaces/{iface}/conf-peers", a.auth(a.confPeers))
	mux.HandleFunc("GET /v1/interfaces/{iface}/conf", a.auth(a.conf))
	mux.HandleFunc("POST /v1/interfaces/{iface}/verify", a.auth(a.verify))
	mux.HandleFunc("PUT /v1/interfaces/{iface}/peers/{pub}", a.auth(a.putPeer))
	mux.HandleFunc("DELETE /v1/interfaces/{iface}/peers/{pub}", a.auth(a.deletePeer))
	mux.HandleFunc("POST /v1/interfaces/{iface}/reconcile", a.auth(a.reconcile))
	mux.HandleFunc("GET /v1/samples", a.auth(a.samples))
}

func (a *API) auth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.Token == "" {
			http.Error(w, `{"error":"node token is not configured"}`, http.StatusServiceUnavailable)
			return
		}
		got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if subtle.ConstantTimeCompare([]byte(got), []byte(a.Token)) != 1 {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]string{"error": err.Error()})
}

func ctxOf(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 15*time.Second)
}

func (a *API) health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := ctxOf(r)
	defer cancel()
	h := Health{Version: version.Version, API: version.API}
	h.AWGVersion, _ = a.Node.Tool.Version(ctx)
	if infos, err := a.Node.Discover(ctx); err == nil {
		for _, i := range infos {
			h.Interfaces = append(h.Interfaces, i.Name)
		}
	}
	h.ForeignManager = a.Node.ForeignManagerActive(ctx)
	if a.Samples != nil {
		h.Buffered = a.Samples.Len()
		h.BufferedFrom = a.Samples.Oldest()
	}
	writeJSON(w, 200, h)
}

func (a *API) host(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := ctxOf(r)
	defer cancel()
	info, err := a.Node.Metrics.Info(ctx)
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, info)
}

func (a *API) metrics(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := ctxOf(r)
	defer cancel()
	s, err := a.Node.Metrics.Snapshot(ctx)
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, s)
}

func (a *API) interfaces(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := ctxOf(r)
	defer cancel()
	infos, err := a.Node.Discover(ctx)
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, infos)
}

type dumpPeer struct {
	PublicKey       string   `json:"public_key"`
	HasPSK          bool     `json:"has_psk"`
	Endpoint        string   `json:"endpoint,omitempty"`
	AllowedIPs      []string `json:"allowed_ips"`
	LatestHandshake int64    `json:"latest_handshake"`
	Rx              uint64   `json:"rx"`
	Tx              uint64   `json:"tx"`
	Keepalive       int      `json:"keepalive"`
}

func (a *API) dump(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := ctxOf(r)
	defer cancel()
	id, peers, err := a.Node.Dump(ctx, r.PathValue("iface"))
	if err != nil {
		fail(w, 500, err)
		return
	}
	out := struct {
		PublicKey  string            `json:"public_key"`
		ListenPort int               `json:"listen_port"`
		IsAWG      bool              `json:"is_awg"`
		Obf        map[string]string `json:"obfuscation"`
		Peers      []dumpPeer        `json:"peers"`
		At         int64             `json:"at"`
	}{PublicKey: id.PublicKey, ListenPort: id.ListenPort, IsAWG: id.IsAWG, Obf: id.Obfuscation12(), At: time.Now().Unix(), Peers: []dumpPeer{}}
	for _, p := range peers {
		var hs int64
		if !p.LatestHandshake.IsZero() {
			hs = p.LatestHandshake.Unix()
		}
		out.Peers = append(out.Peers, dumpPeer{PublicKey: p.PublicKey, HasPSK: p.HasPSK, Endpoint: p.Endpoint, AllowedIPs: p.AllowedIPs, LatestHandshake: hs, Rx: p.Rx, Tx: p.Tx, Keepalive: p.Keepalive})
	}
	writeJSON(w, 200, out)
}

func (a *API) confPeers(w http.ResponseWriter, r *http.Request) {
	peers, err := a.Node.ConfPeers(r.PathValue("iface"))
	if err != nil {
		fail(w, 500, err)
		return
	}
	type cp struct {
		PublicKey  string   `json:"public_key"`
		HasPSK     bool     `json:"has_psk"`
		AllowedIPs []string `json:"allowed_ips"`
		Endpoint   string   `json:"endpoint,omitempty"`
		Keepalive  string   `json:"keepalive,omitempty"`
		Extra      []awg.KV `json:"extra,omitempty"`
	}
	out := make([]cp, 0, len(peers))
	for _, p := range peers {
		out = append(out, cp{PublicKey: p.PublicKey, HasPSK: p.PresharedKey != "", AllowedIPs: p.AllowedIPs, Endpoint: p.Endpoint, Keepalive: p.PersistentKeepalive, Extra: p.Extra})
	}
	writeJSON(w, 200, out)
}

func (a *API) verify(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := ctxOf(r)
	defer cancel()
	res, err := a.Node.Verify(ctx, r.PathValue("iface"))
	if err != nil {
		fail(w, 500, err)
		return
	}
	writeJSON(w, 200, res)
}

// peerBody — тело PUT /v1/interfaces/{iface}/peers/{pub}. Приватных ключей клиента здесь нет:
// узел их не получает и не хранит (SPEC §9).
type peerBody struct {
	PresharedKey string   `json:"preshared_key,omitempty"`
	AllowedIPs   []string `json:"allowed_ips"`
	ClearPSK     bool     `json:"clear_psk,omitempty"`
}

// failWrite отвечает 409 на отказ охранной проверки и 500 на прочие ошибки записи:
// хабу нужно различать «сейчас нельзя» и «сломалось».
func failWrite(w http.ResponseWriter, err error) {
	var ge *GuardError
	if errors.As(err, &ge) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": err.Error(), "guard": ge.Reason})
		return
	}
	fail(w, http.StatusInternalServerError, err)
}

func (a *API) putPeer(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := ctxOf(r)
	defer cancel()
	var body peerBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	spec := awg.PeerSpec{PublicKey: r.PathValue("pub"), PresharedKey: body.PresharedKey, AllowedIPs: body.AllowedIPs, ClearPSK: body.ClearPSK}
	if err := a.Node.ApplyPeer(ctx, r.PathValue("iface"), spec); err != nil {
		failWrite(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "public_key": spec.PublicKey})
}

func (a *API) deletePeer(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := ctxOf(r)
	defer cancel()
	if err := a.Node.RemovePeer(ctx, r.PathValue("iface"), r.PathValue("pub")); err != nil {
		failWrite(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "public_key": r.PathValue("pub")})
}

func (a *API) reconcile(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := ctxOf(r)
	defer cancel()
	var body struct {
		Peers []struct {
			PublicKey    string   `json:"public_key"`
			PresharedKey string   `json:"preshared_key,omitempty"`
			AllowedIPs   []string `json:"allowed_ips"`
		} `json:"peers"`
		AllowEmpty bool `json:"allow_empty,omitempty"`
		DryRun     bool `json:"dry_run,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<20)).Decode(&body); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	desired := make([]awg.PeerSpec, 0, len(body.Peers))
	for _, p := range body.Peers {
		desired = append(desired, awg.PeerSpec{PublicKey: p.PublicKey, PresharedKey: p.PresharedKey, AllowedIPs: p.AllowedIPs})
	}
	if body.DryRun {
		// Примерка: хабу нужно показать администратору, что изменится, ничего не трогая.
		res, _, err := a.Node.PlanReconcile(ctx, r.PathValue("iface"), desired, body.AllowEmpty)
		if err != nil {
			failWrite(w, err)
			return
		}
		writeJSON(w, http.StatusOK, res)
		return
	}
	res, err := a.Node.Reconcile(ctx, r.PathValue("iface"), desired, body.AllowEmpty)
	if err != nil {
		failWrite(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// conf отдаёт файл конфига интерфейса как есть: он нужен копиям и параметрам интерфейса,
// которых нет в дампе рантайма. Внутри приватный ключ сервера, поэтому ручка живёт за тем же
// токеном и тем же loopback, что и остальные.
func (a *API) conf(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("iface")
	body, err := a.Node.ConfRaw(name)
	if err != nil {
		fail(w, http.StatusNotFound, err)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(body)
}

// samples отдаёт накопленные выборки новее since: так хаб добирает то, что прошло мимо него,
// пока связь была порвана (FR-10.4).
func (a *API) samples(w http.ResponseWriter, r *http.Request) {
	if a.Samples == nil {
		writeJSON(w, http.StatusOK, []Sample{})
		return
	}
	var since time.Time
	if v := r.URL.Query().Get("since"); v != "" {
		sec, err := strconv.ParseInt(v, 10, 64)
		if err != nil {
			fail(w, http.StatusBadRequest, fmt.Errorf("since: ожидается unix-время, получено %q", v))
			return
		}
		since = time.Unix(sec, 0)
	}
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		limit, _ = strconv.Atoi(v)
	}
	writeJSON(w, http.StatusOK, a.Samples.Since(since, limit))
}
