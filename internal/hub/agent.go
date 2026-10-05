package hub

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/poznik/awgdash-pub/internal/awg"
	"github.com/poznik/awgdash-pub/internal/hostmetrics"
	"github.com/poznik/awgdash-pub/internal/node"
	"github.com/poznik/awgdash-pub/internal/nodeclient"
	"github.com/poznik/awgdash-pub/internal/store"
	"github.com/poznik/awgdash-pub/internal/version"
)

// Agent — узел глазами хаба: локальный он или на другом сервере, для хаба разницы нет
// (SPEC FR-10.3). Набор операций повторяет контракт §9.
type Agent interface {
	Discover(ctx context.Context) ([]node.InterfaceInfo, error)
	Dump(ctx context.Context, iface string) (*awg.InterfaceDump, []awg.PeerDump, error)
	ConfPeers(ctx context.Context, iface string) ([]awg.Peer, error)
	ConfRaw(ctx context.Context, iface string) ([]byte, error)
	Verify(ctx context.Context, iface string) (awg.VerifyResult, error)
	ForeignManagerActive(ctx context.Context) string
	ApplyPeer(ctx context.Context, iface string, spec awg.PeerSpec) error
	RemovePeer(ctx context.Context, iface, pub string) error
	Reconcile(ctx context.Context, iface string, desired []awg.PeerSpec, allowEmpty bool) (node.ReconcileResult, error)
	PlanReconcile(ctx context.Context, iface string, desired []awg.PeerSpec, allowEmpty bool) (node.ReconcileResult, error)
	HostInfo(ctx context.Context) (hostmetrics.HostInfo, error)
	HostMetrics(ctx context.Context) (hostmetrics.Snapshot, error)
	AWGVersion(ctx context.Context) (string, error)
	// NodeVersion — версия самого awgdash на той машине. У удалённого узла она своя: парк
	// обновляется по одной машине, и разошедшиеся версии ведут себя по-разному (FR-10.5).
	NodeVersion(ctx context.Context) (string, error)
	// Samples — выборки, накопленные узлом после указанного момента (FR-10.4).
	// Локальный узел буфера не ведёт и возвращает пустой список.
	Samples(ctx context.Context, since time.Time, limit int) ([]node.Sample, error)
	// ConfPath — путь конфига на той машине. Хабу он нужен для манифеста копий и сообщений,
	// читается файл всё равно через ConfRaw.
	ConfPath(iface string) string
}

// LocalAgent — узел в том же процессе (фаза 1 и сервер, где живёт сам хаб).
type LocalAgent struct{ N *node.Node }

func (a LocalAgent) Discover(ctx context.Context) ([]node.InterfaceInfo, error) {
	return a.N.Discover(ctx)
}

func (a LocalAgent) Dump(ctx context.Context, iface string) (*awg.InterfaceDump, []awg.PeerDump, error) {
	return a.N.Dump(ctx, iface)
}

func (a LocalAgent) ConfPeers(_ context.Context, iface string) ([]awg.Peer, error) {
	return a.N.ConfPeers(iface)
}

func (a LocalAgent) ConfRaw(_ context.Context, iface string) ([]byte, error) {
	return a.N.ConfRaw(iface)
}

func (a LocalAgent) Verify(ctx context.Context, iface string) (awg.VerifyResult, error) {
	return a.N.Verify(ctx, iface)
}

func (a LocalAgent) ForeignManagerActive(ctx context.Context) string {
	return a.N.ForeignManagerActive(ctx)
}

func (a LocalAgent) ApplyPeer(ctx context.Context, iface string, spec awg.PeerSpec) error {
	return a.N.ApplyPeer(ctx, iface, spec)
}

func (a LocalAgent) RemovePeer(ctx context.Context, iface, pub string) error {
	return a.N.RemovePeer(ctx, iface, pub)
}

func (a LocalAgent) Reconcile(ctx context.Context, iface string, desired []awg.PeerSpec, allowEmpty bool) (node.ReconcileResult, error) {
	return a.N.Reconcile(ctx, iface, desired, allowEmpty)
}

func (a LocalAgent) PlanReconcile(ctx context.Context, iface string, desired []awg.PeerSpec, allowEmpty bool) (node.ReconcileResult, error) {
	res, _, err := a.N.PlanReconcile(ctx, iface, desired, allowEmpty)
	return res, err
}

func (a LocalAgent) HostInfo(ctx context.Context) (hostmetrics.HostInfo, error) {
	return a.N.Metrics.Info(ctx)
}

func (a LocalAgent) HostMetrics(ctx context.Context) (hostmetrics.Snapshot, error) {
	return a.N.Metrics.Snapshot(ctx)
}

func (a LocalAgent) AWGVersion(ctx context.Context) (string, error) { return a.N.Tool.Version(ctx) }

// NodeVersion локального узла — версия этого же процесса.
func (a LocalAgent) NodeVersion(context.Context) (string, error) { return version.Version, nil }

func (a LocalAgent) ConfPath(iface string) string { return a.N.ConfPath(iface) }

// Samples у локального узла пуст: хаб опрашивает свою машину напрямую, копить нечего.
func (a LocalAgent) Samples(context.Context, time.Time, int) ([]node.Sample, error) {
	return nil, nil
}

// remoteAgent — узел на другом сервере. Отдельный тип нужен только чтобы дописать ConfPath:
// путь на той машине хаб знает из настроек сервера, а не из своей файловой системы.
type remoteAgent struct {
	*nodeclient.Client
	confDir string
}

func (a remoteAgent) ConfPath(iface string) string { return a.confDir + "/" + iface + ".conf" }

// Server — сервер парка вместе со своим узлом.
type Server struct {
	ID    int64
	Slug  string
	Title string
	Local bool
	Agent Agent
}

// servers — реестр узлов, с которыми работает хаб. Локальный всегда на месте; удалённые
// приезжают из БД при старте и по команде «добавить сервер».
type servers struct {
	mu sync.RWMutex
	m  map[int64]*Server
}

func newServers() *servers { return &servers{m: map[int64]*Server{}} }

func (s *servers) put(srv *Server) {
	s.mu.Lock()
	s.m[srv.ID] = srv
	s.mu.Unlock()
}

func (s *servers) drop(id int64) {
	s.mu.Lock()
	delete(s.m, id)
	s.mu.Unlock()
}

func (s *servers) get(id int64) (*Server, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	srv, ok := s.m[id]
	return srv, ok
}

func (s *servers) all() []*Server {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Server, 0, len(s.m))
	for _, srv := range s.m {
		out = append(out, srv)
	}
	return out
}

// Agent возвращает узел сервера. Ошибка вместо nil намеренно: молча ничего не сделать
// на неизвестном сервере — худший из возможных исходов записи.
func (h *Hub) Agent(serverID int64) (Agent, error) {
	if srv, ok := h.servers.get(serverID); ok {
		return srv.Agent, nil
	}
	// Локальный узел живёт в этом же процессе и доступен всегда — реестр наполняется при
	// старте хаба, а разовые команды CLI работают и без него.
	if h.Node != nil && (serverID == h.ServerID || serverID == 0) {
		return LocalAgent{N: h.Node}, nil
	}
	return nil, fmt.Errorf("сервер %d не зарегистрирован в панели", serverID)
}

// AgentForInterface — узел, на котором живёт интерфейс.
func (h *Hub) AgentForInterface(ctx context.Context, ifaceID int64) (Agent, store.Interface, error) {
	iface, err := h.Interface(ctx, ifaceID)
	if err != nil {
		return nil, iface, err
	}
	a, err := h.Agent(iface.ServerID)
	return a, iface, err
}

// Servers — все известные серверы (для циклов обхода и страниц).
func (h *Hub) Servers() []*Server { return h.servers.all() }

// newRemoteAgent собирает узел по записи сервера: транспорт всегда loopback — до удалённой
// машины ведёт ssh-туннель, поднятый отдельным юнитом (решение фазы 2).
func newRemoteAgent(s store.Server, token, confDir string) Agent {
	port := s.NodePort
	if port == 0 {
		port = 10089
	}
	c := nodeclient.New(fmt.Sprintf("http://127.0.0.1:%d", port), token)
	if confDir == "" {
		confDir = "/etc/amnezia/amneziawg"
	}
	return remoteAgent{Client: c, confDir: confDir}
}
