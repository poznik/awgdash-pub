// Package nodeclient — хаб, разговаривающий с удалённым узлом по его же HTTP-контракту
// (SPEC §9, FR-10.1). Транспорт — ssh-туннель: узел слушает loopback у себя, хаб ходит
// на localhost:порт у себя, наружу не публикуется ничего.
package nodeclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/awg"
	"github.com/poznik/awgdash-pub/internal/hostmetrics"
	"github.com/poznik/awgdash-pub/internal/node"
	"github.com/poznik/awgdash-pub/internal/version"
)

// Client — узел на другом сервере. Методы повторяют локальный *node.Node: хаб не должен
// знать, где живёт узел.
type Client struct {
	Base  string // http://127.0.0.1:10089
	Token string
	HTTP  *http.Client

	// ConfDir — каталог конфигов на той машине. Нужен только для сообщений и манифеста копий:
	// файлы читаются через API.
	ConfDir string
}

// New собирает клиента с разумными таймаутами: запись пира идёт через `awg set` на той стороне,
// а обход интерфейсов читает /proc — секунды, не минуты.
func New(base, token string) *Client {
	return &Client{
		Base:  strings.TrimSuffix(base, "/"),
		Token: token,
		HTTP:  &http.Client{Timeout: 30 * time.Second},
	}
}

// Error — ответ узла об отказе. Код важен: 401 значит «токен разъехался», 409 — охранная
// проверка на узле, 503 — узел поднят без токена.
type Error struct {
	Code    int
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("узел ответил %d: %s", e.Code, e.Message)
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Base+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("узел %s недоступен: %w", c.Base, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var e struct {
			Error string `json:"error"`
		}
		json.Unmarshal(raw, &e)
		msg := e.Error
		if msg == "" {
			msg = strings.TrimSpace(string(raw))
		}
		return &Error{Code: resp.StatusCode, Message: msg}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(raw, out)
}

// Health — версия и состояние узла; по ней хаб решает, совместим ли он с этим агентом.
func (c *Client) Health(ctx context.Context) (node.Health, error) {
	var h node.Health
	err := c.do(ctx, http.MethodGet, "/v1/health", nil, &h)
	return h, err
}

// CheckCompatible отвергает узел с чужой версией API: молча работать с несовместимым
// контрактом опаснее, чем не работать вовсе (FR-10.5).
func (c *Client) CheckCompatible(ctx context.Context) (node.Health, error) {
	h, err := c.Health(ctx)
	if err != nil {
		return h, err
	}
	if h.API != version.API {
		return h, fmt.Errorf("узел говорит на версии API %d, панель — на %d: обновите обе стороны", h.API, version.API)
	}
	return h, nil
}

// Discover — интерфейсы узла.
func (c *Client) Discover(ctx context.Context) ([]node.InterfaceInfo, error) {
	var out []node.InterfaceInfo
	err := c.do(ctx, http.MethodGet, "/v1/interfaces", nil, &out)
	return out, err
}

// Dump — рантайм интерфейса: сам интерфейс и пиры со счётчиками. Ответ узла плоский,
// время хендшейка приходит числом — разворачиваем в те же типы, что у локального узла.
func (c *Client) Dump(ctx context.Context, iface string) (*awg.InterfaceDump, []awg.PeerDump, error) {
	var out struct {
		PublicKey  string            `json:"public_key"`
		ListenPort int               `json:"listen_port"`
		IsAWG      bool              `json:"is_awg"`
		Obf        map[string]string `json:"obfuscation"`
		Peers      []struct {
			PublicKey       string   `json:"public_key"`
			HasPSK          bool     `json:"has_psk"`
			Endpoint        string   `json:"endpoint"`
			AllowedIPs      []string `json:"allowed_ips"`
			LatestHandshake int64    `json:"latest_handshake"`
			Rx              uint64   `json:"rx"`
			Tx              uint64   `json:"tx"`
			Keepalive       int      `json:"keepalive"`
		} `json:"peers"`
	}
	if err := c.do(ctx, http.MethodGet, "/v1/interfaces/"+iface+"/dump", nil, &out); err != nil {
		return nil, nil, err
	}
	id := &awg.InterfaceDump{PublicKey: out.PublicKey, ListenPort: out.ListenPort, IsAWG: out.IsAWG, Obf: out.Obf}
	peers := make([]awg.PeerDump, 0, len(out.Peers))
	for _, p := range out.Peers {
		var hs time.Time
		if p.LatestHandshake > 0 {
			hs = time.Unix(p.LatestHandshake, 0)
		}
		peers = append(peers, awg.PeerDump{PublicKey: p.PublicKey, HasPSK: p.HasPSK, Endpoint: p.Endpoint,
			AllowedIPs: p.AllowedIPs, LatestHandshake: hs, Rx: p.Rx, Tx: p.Tx, Keepalive: p.Keepalive})
	}
	return id, peers, nil
}

// ConfPeers — пиры из файла конфига (не из рантайма).
func (c *Client) ConfPeers(ctx context.Context, iface string) ([]awg.Peer, error) {
	var out []awg.Peer
	err := c.do(ctx, http.MethodGet, "/v1/interfaces/"+iface+"/conf-peers", nil, &out)
	return out, err
}

// ConfRaw — файл конфига целиком (копии и параметры интерфейса).
func (c *Client) ConfRaw(ctx context.Context, iface string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"/v1/interfaces/"+iface+"/conf", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("узел %s недоступен: %w", c.Base, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, &Error{Code: resp.StatusCode, Message: strings.TrimSpace(string(raw))}
	}
	return raw, nil
}

// Verify — сверка обфускации файла и рантайма.
func (c *Client) Verify(ctx context.Context, iface string) (awg.VerifyResult, error) {
	var out awg.VerifyResult
	err := c.do(ctx, http.MethodPost, "/v1/interfaces/"+iface+"/verify", nil, &out)
	return out, err
}

// HostInfo — редко меняющиеся факты о машине.
func (c *Client) HostInfo(ctx context.Context) (hostmetrics.HostInfo, error) {
	var out hostmetrics.HostInfo
	err := c.do(ctx, http.MethodGet, "/v1/host", nil, &out)
	return out, err
}

// HostMetrics — текущие метрики.
func (c *Client) HostMetrics(ctx context.Context) (hostmetrics.Snapshot, error) {
	var out hostmetrics.Snapshot
	err := c.do(ctx, http.MethodGet, "/v1/host/metrics", nil, &out)
	return out, err
}

// NodeVersion — версия панели на самой машине узла: обновляются они по одной.
func (c *Client) NodeVersion(ctx context.Context) (string, error) {
	h, err := c.Health(ctx)
	return h.Version, err
}

// AWGVersion — версия инструментов на узле.
func (c *Client) AWGVersion(ctx context.Context) (string, error) {
	h, err := c.Health(ctx)
	return h.AWGVersion, err
}

// ForeignManagerActive — чужой менеджер пиров на узле (пусто, если чисто).
func (c *Client) ForeignManagerActive(ctx context.Context) string {
	h, err := c.Health(ctx)
	if err != nil {
		return ""
	}
	return h.ForeignManager
}

type peerBody struct {
	PresharedKey string   `json:"preshared_key,omitempty"`
	AllowedIPs   []string `json:"allowed_ips"`
}

// ApplyPeer ставит пир на интерфейс узла (идемпотентно).
func (c *Client) ApplyPeer(ctx context.Context, iface string, spec awg.PeerSpec) error {
	return c.do(ctx, http.MethodPut, "/v1/interfaces/"+iface+"/peers/"+urlKey(spec.PublicKey),
		peerBody{PresharedKey: spec.PresharedKey, AllowedIPs: spec.AllowedIPs}, nil)
}

// RemovePeer снимает пир.
func (c *Client) RemovePeer(ctx context.Context, iface, pub string) error {
	return c.do(ctx, http.MethodDelete, "/v1/interfaces/"+iface+"/peers/"+urlKey(pub), nil, nil)
}

type reconcileBody struct {
	Peers      []peerSpecJSON `json:"peers"`
	AllowEmpty bool           `json:"allow_empty,omitempty"`
	DryRun     bool           `json:"dry_run,omitempty"`
}

type peerSpecJSON struct {
	PublicKey    string   `json:"public_key"`
	PresharedKey string   `json:"preshared_key,omitempty"`
	AllowedIPs   []string `json:"allowed_ips"`
}

// Reconcile приводит интерфейс узла к списку пиров.
func (c *Client) Reconcile(ctx context.Context, iface string, desired []awg.PeerSpec, allowEmpty bool) (node.ReconcileResult, error) {
	return c.reconcile(ctx, iface, desired, allowEmpty, false)
}

// PlanReconcile — та же сверка без записи: показать администратору, что изменится.
func (c *Client) PlanReconcile(ctx context.Context, iface string, desired []awg.PeerSpec, allowEmpty bool) (node.ReconcileResult, error) {
	return c.reconcile(ctx, iface, desired, allowEmpty, true)
}

func (c *Client) reconcile(ctx context.Context, iface string, desired []awg.PeerSpec, allowEmpty, dry bool) (node.ReconcileResult, error) {
	body := reconcileBody{AllowEmpty: allowEmpty, DryRun: dry}
	for _, p := range desired {
		body.Peers = append(body.Peers, peerSpecJSON{PublicKey: p.PublicKey, PresharedKey: p.PresharedKey, AllowedIPs: p.AllowedIPs})
	}
	var out node.ReconcileResult
	err := c.do(ctx, http.MethodPost, "/v1/interfaces/"+iface+"/reconcile", body, &out)
	return out, err
}

// urlKey кодирует публичный ключ для пути: в base64 встречаются «/» и «+».
func urlKey(pub string) string {
	r := strings.NewReplacer("/", "%2F", "+", "%2B", "=", "%3D")
	return r.Replace(pub)
}

// Samples забирает выборки, накопленные узлом после указанного момента (FR-10.4).
// Пустой since означает «всё, что есть в буфере».
// maxResponse — потолок ответа узла. Восемь мегабайт казались щедрыми, пока узел не накопил
// суточный буфер выборок: ответ на 12 МБ обрезался ровно посередине JSON, выборка падала с
// «unexpected end of JSON input», курсор не двигался — и панель переставала видеть, кто в
// туннеле, хотя туннель работал. Полный буфер (6000 выборок по 60+ пиров) укладывается сюда.
const maxResponse = 96 << 20

func (c *Client) Samples(ctx context.Context, since time.Time, limit int) ([]node.Sample, error) {
	path := "/v1/samples"
	q := ""
	if !since.IsZero() {
		q = "?since=" + strconv.FormatInt(since.Unix(), 10)
	}
	if limit > 0 {
		sep := "?"
		if q != "" {
			sep = "&"
		}
		q += sep + "limit=" + strconv.Itoa(limit)
	}
	var out []node.Sample
	err := c.do(ctx, http.MethodGet, path+q, nil, &out)
	return out, err
}
