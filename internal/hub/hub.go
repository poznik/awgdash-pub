// Package hub — центр: регистрирует локальный узел, опрашивает интерфейсы, копит статистику и события.
// Фаза 1: режим observe, хаб и узел в одном процессе.
package hub

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/poznik/awgdash-pub/internal/awg"
	"github.com/poznik/awgdash-pub/internal/config"
	"github.com/poznik/awgdash-pub/internal/node"
	"github.com/poznik/awgdash-pub/internal/nodeclient"
	"github.com/poznik/awgdash-pub/internal/store"
	"github.com/poznik/awgdash-pub/internal/telegram"
	"github.com/poznik/awgdash-pub/internal/version"
)

// OnlineThreshold — хендшейк не старше этого = онлайн (SPEC FR-6.2); порог общий с запросами хранилища.
const OnlineThreshold = store.OnlineWindow

// rollupEvery — как часто пересчитываются агрегаты; maxRollup — потолок разового пересчёта,
// чтобы догнанный после долгой разлуки узел не заставил перебрать всю историю разом.
const (
	rollupEvery = 5 * time.Minute
	maxRollup   = 14 * 24 * time.Hour
)

// LiveSampleEvery — как часто интерфейс опрашивается, пока открыта живая страница (FR-6.1).
const LiveSampleEvery = 5 * time.Second

// ifaceRef — интерфейс в обходе: как называется и на какой машине живёт.
type ifaceRef struct {
	Name     string
	ServerID int64
}

// Hub — состояние хаба.
type Hub struct {
	Cfg   *config.Config
	Store *store.Store
	Node  *node.Node
	Log   *slog.Logger
	// Bot — оповещатель, если включён. Хаб пишет события в БД в любом случае; бот их разбирает.
	Bot *telegram.Bot

	// ServerID — локальный сервер: на нём живёт панель, к нему привязаны её собственные события.
	ServerID int64
	// servers — все узлы парка (локальный и удалённые), см. agent.go.
	servers *servers

	mu sync.Mutex
	// ifaces — что панель обходит: ключ — идентификатор интерфейса. По имени ключевать нельзя:
	// одно и то же имя живёт на разных машинах парка (три `awg-hub` между серверами), и карта
	// по имени оставляла в обходе один интерфейс из трёх — остальные молча переставали
	// опрашиваться и сверяться.
	ifaces     map[int64]ifaceRef
	unitState  map[int64]bool
	verifyOK   map[int64]bool
	lastSample time.Time
	foreign    string           // чужой менеджер на локальном узле (обновляется сверкой)
	foreignBy  map[int64]string // то же по каждому серверу парка
	lastErr    string
	peersNow   map[int64]int
	onlineNow  map[int64]int
	liveSample map[int64]time.Time // когда интерфейс опрашивался вне очереди
	// appliedAt — до какого момента выборки узла уже разобраны: по нему хаб добирает
	// пропущенное из буфера удалённого узла (FR-10.4).
	appliedAt map[int64]time.Time
	started   time.Time
	// alerts помнит, о чём уже сказано: событие пишется на переходе через порог,
	// а не на каждой проверке.
	alerts         map[string]bool
	nodeDown       bool
	sampleFailedAt time.Time
	dirtyAt        time.Time // когда состояние изменилось: копия снимается через debounce
}

// New создаёт хаб поверх открытого хранилища и локального узла.
func New(cfg *config.Config, st *store.Store, n *node.Node, log *slog.Logger) *Hub {
	return &Hub{Cfg: cfg, Store: st, Node: n, Log: log, ifaces: map[int64]ifaceRef{}, foreignBy: map[int64]string{}, unitState: map[int64]bool{},
		verifyOK: map[int64]bool{}, peersNow: map[int64]int{}, onlineNow: map[int64]int{},
		liveSample: map[int64]time.Time{}, appliedAt: map[int64]time.Time{}, alerts: map[string]bool{},
		servers: newServers(), started: time.Now()}
}

// Status — сводка для /healthz и страницы наблюдения.
type Status struct {
	Version    string    `json:"version"`
	Uptime     string    `json:"uptime"`
	ServerID   int64     `json:"server_id"`
	LastSample time.Time `json:"last_sample"`
	LastError  string    `json:"last_error,omitempty"`
	// Peers и Online — по идентификатору интерфейса: имена в парке повторяются.
	Peers  map[int64]int `json:"peers"`
	Online map[int64]int `json:"online"`
}

// Status возвращает текущую сводку.
func (h *Hub) Status() Status {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := Status{Version: version.Version, Uptime: time.Since(h.started).Round(time.Second).String(), ServerID: h.ServerID, LastSample: h.lastSample, LastError: h.lastErr, Peers: map[int64]int{}, Online: map[int64]int{}}
	for k, v := range h.peersNow {
		s.Peers[k] = v
	}
	for k, v := range h.onlineNow {
		s.Online[k] = v
	}
	return s
}

// Start регистрирует сервер, делает первый обход и запускает фоновые циклы до отмены ctx.
func (h *Hub) Start(ctx context.Context) error {
	id, err := h.Store.UpsertLocalServer(ctx, h.Cfg.ServerSlug, h.Cfg.ServerTitle)
	if err != nil {
		return err
	}
	h.ServerID = id
	h.registerLocal()
	if err := h.LoadServers(ctx); err != nil {
		h.Log.Warn("реестр серверов", "err", err)
	}
	t0 := time.Now()
	h.touchServers(ctx)
	t1 := time.Now()
	if err := h.discover(ctx); err != nil {
		h.Log.Warn("обнаружение интерфейсов", "err", err)
	}
	h.Log.Info("старт хаба", "server_id", id, "touch", t1.Sub(t0).Round(time.Millisecond), "discover", time.Since(t1).Round(time.Millisecond))
	h.Store.AddEvent(ctx, store.Event{Kind: "panel_started", ServerID: id, Message: "панель запущена · " + version.Version})
	go h.loop(ctx, h.Cfg.SampleEvery, "sample", h.sampleAll)
	go h.loop(ctx, h.Cfg.MetricsEvery, "metrics", h.metrics)
	go h.loop(ctx, 5*time.Minute, "verify", h.verifyAll)
	go h.loop(ctx, rollupEvery, "rollup", func(ctx context.Context) error { return h.Store.Rollup(ctx, 2*time.Hour) })
	go h.loop(ctx, 6*time.Hour, "retention", h.retention)
	go h.loop(ctx, 10*time.Minute, "discover", func(ctx context.Context) error { h.touchServers(ctx); return h.discover(ctx) })
	go h.loop(ctx, time.Minute, "registry", h.LoadServers)
	go h.loop(ctx, time.Hour, "housekeeping", h.housekeeping)
	go h.loop(ctx, 5*time.Minute, "alerts", h.alertsLoop)
	go h.loop(ctx, time.Minute, "backup", h.backupTick)
	return nil
}

func (h *Hub) loop(ctx context.Context, every time.Duration, name string, fn func(context.Context) error) {
	run := func() {
		c, cancel := context.WithTimeout(ctx, every)
		defer cancel()
		if err := fn(c); err != nil {
			h.Log.Warn(name, "err", err)
			h.mu.Lock()
			h.lastErr = name + ": " + err.Error()
			h.mu.Unlock()
		}
	}
	run()
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			run()
		}
	}
}

// retention чистит наблюдение и журналы: аудит и события копятся от каждого действия и от
// каждой неудачной попытки входа, и без срока хранения таблицы растут бесконечно (FR-12.2a).
func (h *Hub) retention(ctx context.Context) error {
	if err := h.Store.Retention(ctx, h.Cfg.RawRetention, h.Cfg.M5Retention); err != nil {
		return err
	}
	audits, events, err := h.Store.PurgeJournals(ctx, h.Cfg.JournalRetention)
	if err != nil {
		return err
	}
	if audits+events > 0 {
		h.Log.Info("журналы прорежены", "аудит", audits, "события", events, "хранение", h.Cfg.JournalRetention)
	}
	return nil
}

// registerLocal кладёт в реестр узел, на котором работает сама панель.
func (h *Hub) registerLocal() {
	h.servers.put(&Server{ID: h.ServerID, Slug: h.Cfg.ServerSlug, Title: h.Cfg.ServerTitle, Local: true, Agent: LocalAgent{N: h.Node}})
}

// LoadServers сверяет реестр узлов с БД: новые и вернувшиеся берёт в работу, выключенные,
// выведенные и удалённые убирает (FR-10.8). Токен у парка общий: он же лежит в .env узла
// (AWGDASH_NODE_TOKEN). Зовётся при старте, раз в минуту и сразу после действий над составом
// парка — иначе панель обещает возобновить опрос, а на деле ждёт перезапуска.
func (h *Hub) LoadServers(ctx context.Context) error {
	list, err := h.Store.Servers(ctx)
	if err != nil {
		return err
	}
	// Локальный узел из реестра не уходит: он живёт в этом же процессе.
	keep := map[int64]bool{h.ServerID: true}
	for _, srv := range list {
		if srv.Local() {
			// В работающем хабе локальный узел уже в реестре (registerLocal при старте), а
			// разовые команды CLI приходят сюда с пустым реестром — без этой ветки парк
			// выглядел бы неполным: `backup now` печатал бы «hel, ru» без самого de.
			if _, ok := h.servers.get(srv.ID); !ok && h.Node != nil {
				h.servers.put(&Server{ID: srv.ID, Slug: srv.Slug, Title: srv.Title, Local: true, Agent: LocalAgent{N: h.Node}})
			}
			keep[srv.ID] = true
			continue
		}
		if !srv.Enabled || srv.Retired() {
			continue
		}
		// Узел, который уже в работе, не переспрашиваем: реестр сверяется раз в минуту,
		// а сверка версии — это запрос к каждой машине парка. Меняться у записи может
		// только название: порт и адрес задаются один раз, при заведении.
		if cur, ok := h.servers.get(srv.ID); ok {
			keep[srv.ID] = true
			if cur.Slug != srv.Slug || cur.Title != srv.Title {
				h.servers.put(&Server{ID: srv.ID, Slug: srv.Slug, Title: srv.Title, Agent: cur.Agent})
			}
			continue
		}
		agent := newRemoteAgent(srv, h.Cfg.NodeToken, h.Cfg.AWGConfDir)
		// Версия API узла сверяется до того, как хаб начнёт им управлять: работать с чужим
		// контрактом молча опаснее, чем не работать вовсе (FR-10.5). Недоступный узел
		// в реестр всё равно попадает — о нём скажет node_down, а связь ещё вернётся.
		if err := h.checkNodeVersion(ctx, srv, agent); err != nil {
			continue
		}
		reg := &Server{ID: srv.ID, Slug: srv.Slug, Title: srv.Title, Agent: agent}
		h.servers.put(reg)
		keep[srv.ID] = true
		// Взяли узел в работу — сразу и осматриваем: иначе его интерфейсы ждали бы
		// очередного обхода, и вернувшийся сервер молчал бы ещё десять минут.
		if err := h.discoverServer(ctx, reg); err != nil {
			h.Log.Warn("обнаружение интерфейсов", "server", srv.Slug, "err", err)
		}
	}
	// Чего в живом списке не оказалось, из реестра уходит: сервер выключен, выведен или
	// удалён — опрашивать нечего.
	for _, srv := range h.servers.all() {
		if !keep[srv.ID] {
			h.servers.drop(srv.ID)
			h.forgetInterfaces(srv.ID)
		}
	}
	return nil
}

// forgetInterfaces убирает интерфейсы ушедшего сервера из обхода. Без этого выборка каждые
// 15 с спотыкалась бы о них и через две минуты объявила бы узел упавшим — а его не чинить
// надо, его вывели или выключили нарочно (FR-10.6). Вернётся в парк — интерфейсы вернёт
// обнаружение.
func (h *Hub) forgetInterfaces(serverID int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, ref := range h.ifaces {
		if ref.ServerID == serverID {
			h.dropIface(id)
		}
	}
}

// dropIface убирает интерфейс из обхода. Зовётся под h.mu.
func (h *Hub) dropIface(id int64) {
	delete(h.ifaces, id)
	delete(h.unitState, id)
	delete(h.appliedAt, id)
	delete(h.liveSample, id)
	delete(h.verifyOK, id)
	delete(h.peersNow, id)
	delete(h.onlineNow, id)
}

// reloadServers сверяет реестр и не мешает вызвавшему действию: запись в БД уже прошла,
// а неудачное чтение реестра — повод для строки в журнале, не для отказа.
func (h *Hub) reloadServers(ctx context.Context) {
	if err := h.LoadServers(ctx); err != nil {
		h.Log.Warn("реестр серверов", "err", err)
	}
}

// checkNodeVersion сверяет версию API узла. Ошибка связи не считается несовместимостью:
// узел может подняться позже, а вот чужая версия контракта — повод не трогать его вовсе.
func (h *Hub) checkNodeVersion(ctx context.Context, srv store.Server, agent Agent) error {
	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	rc, ok := agent.(interface {
		CheckCompatible(context.Context) (node.Health, error)
	})
	if !ok {
		return nil
	}
	if _, err := rc.CheckCompatible(c); err != nil {
		var apiErr *nodeclient.Error
		if errors.As(err, &apiErr) || strings.Contains(err.Error(), "недоступен") {
			h.Log.Warn("узел не отвечает", "server", srv.Slug, "err", err)
			return nil
		}
		h.Log.Error("узел несовместим", "server", srv.Slug, "err", err)
		// Реестр сверяется раз в минуту — о чужом контракте говорим один раз, пока узел
		// не станет совместимым (FR-10.8).
		if h.markAlert("incompatible/"+srv.Slug, true) {
			h.eventOn(ctx, srv.ID, "node_incompatible", "crit", 0, 0,
				"узел "+srv.Slug+" не берётся в работу: "+err.Error())
		}
		return err
	}
	h.markAlert("incompatible/"+srv.Slug, false)
	return nil
}

// touchServers обновляет факты о каждой машине парка. Недоступный узел не мешает остальным:
// ошибки собираются в журнал, а не прерывают обход.
func (h *Hub) touchServers(ctx context.Context) {
	for _, srv := range h.servers.all() {
		h.touchServer(ctx, srv)
	}
}

func (h *Hub) touchServer(ctx context.Context, srv *Server) {
	t0 := time.Now()
	info, err := srv.Agent.HostInfo(ctx)
	if err != nil {
		h.Log.Warn("host info", "server", srv.Slug, "err", err)
	}
	ver, err := srv.Agent.AWGVersion(ctx)
	if err != nil {
		h.Log.Warn("awg --version", "server", srv.Slug, "err", err)
	}
	snap, err := srv.Agent.HostMetrics(ctx)
	if err != nil {
		h.Log.Warn("host metrics", "server", srv.Slug, "err", err)
	}
	// Версия панели у удалённого узла своя: парк обновляется по одной машине, и на старом узле
	// то же действие ведёт себя иначе — сверка обфускации на узле от 24.08 считала «пусто» и
	// «0» разными состояниями и красила исправный интерфейс.
	agentVersion, err := srv.Agent.NodeVersion(ctx)
	if err != nil {
		h.Log.Warn("версия узла", "server", srv.Slug, "err", err)
		agentVersion = ""
	}
	if err := h.Store.TouchServer(ctx, srv.ID, info.PublicIP, info.EgressIface, info.Kernel, ver, agentVersion, snap.RebootRequired); err != nil {
		h.Log.Warn("touch server", "server", srv.Slug, "err", err)
	}
	h.Log.Debug("touchServer", "server", srv.Slug, "заняло", time.Since(t0).Round(time.Millisecond))
}

// discover обходит все узлы парка: обновляет таблицу интерфейсов по их конфигам и отмечает
// смену состояния юнитов. Недоступный узел не отменяет обход остальных.
func (h *Hub) discover(ctx context.Context) error {
	var firstErr error
	for _, srv := range h.servers.all() {
		if err := h.discoverServer(ctx, srv); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", srv.Slug, err)
		}
	}
	return firstErr
}

func (h *Hub) discoverServer(ctx context.Context, srv *Server) error {
	infos, err := srv.Agent.Discover(ctx)
	if err != nil {
		return err
	}
	present := make([]string, 0, len(infos))
	for _, i := range infos {
		present = append(present, i.Name)
	}
	for _, i := range infos {
		id, err := h.Store.UpsertInterface(ctx, srv.ID, i.Name, store.InterfaceFacts{ConfPath: i.ConfPath, Subnet: i.Subnet, ServerAddress: i.Address, ListenPort: i.ListenPort, MTU: i.MTU,
			ServerPublicKey: i.ServerPublicKey, Obfuscation: i.Obfuscation, IsAWG: i.IsAWG, SaveConfig: i.SaveConfig, UnitActive: i.UnitActive, ConfMtime: i.ConfMtime})
		if err != nil {
			return err
		}
		h.ensureEndpoint(ctx, srv, id, i)
		h.mu.Lock()
		h.ifaces[id] = ifaceRef{Name: i.Name, ServerID: srv.ID}
		prev, known := h.unitState[id]
		h.unitState[id] = i.UnitActive
		h.mu.Unlock()
		if known && prev != i.UnitActive {
			kind, sev, msg := "iface_up", "info", "интерфейс "+i.Name+" поднялся"
			if !i.UnitActive {
				kind, sev, msg = "iface_down", "crit", "интерфейс "+i.Name+": юнит awg-quick@"+i.Name+" неактивен"
			}
			h.Store.AddEvent(ctx, store.Event{Kind: kind, Severity: sev, ServerID: srv.ID, InterfaceID: id, Message: msg})
		}
		if i.DumpError != "" {
			h.Store.SetInterfaceStatus(ctx, id, "dump-error", i.UnitActive)
		}
	}
	h.noteGone(ctx, srv, present)
	if err := h.Store.TouchServerSeen(ctx, srv.ID); err != nil {
		h.Log.Warn("отметка связи", "server", srv.Slug, "err", err)
	}
	return nil
}

// noteGone отмечает интерфейсы, которых узел больше не отдаёт: их конфиг сняли с сервера.
// Запись остаётся — на ней висят устройства и история, — но из обхода интерфейс уходит: иначе
// каждые 15 секунд выборка спотыкается об «Unable to access interface» и держит ошибку узла
// в состоянии панели. Убирает запись человек кнопкой (FR-1.9).
func (h *Hub) noteGone(ctx context.Context, srv *Server, present []string) {
	gone, err := h.Store.MarkGoneInterfaces(ctx, srv.ID, present)
	if err != nil {
		h.Log.Warn("пометка пропавших интерфейсов", "server", srv.Slug, "err", err)
		return
	}
	live := map[string]bool{}
	for _, n := range present {
		live[n] = true
	}
	h.mu.Lock()
	for id, ref := range h.ifaces {
		if ref.ServerID == srv.ID && !live[ref.Name] {
			h.dropIface(id)
		}
	}
	h.mu.Unlock()
	for _, name := range gone {
		h.Log.Info("интерфейс исчез с сервера", "server", srv.Slug, "iface", name)
		h.Store.AddEvent(ctx, store.Event{Kind: "iface_gone", Severity: "warn", ServerID: srv.ID,
			Message: "интерфейс " + name + " исчез с сервера " + srv.Title + ": конфига больше нет. Панель держит его записи, пока их не убрать"})
	}
}

// ForgetInterface убирает интерфейс из панели вместе с пирами, устройствами и историей. Зовётся
// только для интерфейса, которого больше нет на сервере: живой убирать незачем — для этого есть
// режим observe (FR-1.9).
func (h *Hub) ForgetInterface(ctx context.Context, id int64, actor, ip string) (store.ServerBelongings, error) {
	iface, err := h.Interface(ctx, id)
	if err != nil {
		return store.ServerBelongings{}, err
	}
	if iface.Status != store.StatusGone {
		return store.ServerBelongings{}, fmt.Errorf("интерфейс %s на сервере на месте — убирать из панели нечего", iface.Name)
	}
	b, err := h.Store.InterfaceBelongings(ctx, id)
	if err != nil {
		return store.ServerBelongings{}, err
	}
	if err := h.Store.DeleteInterface(ctx, id); err != nil {
		return store.ServerBelongings{}, err
	}
	h.mu.Lock()
	h.dropIface(id)
	h.mu.Unlock()
	h.audit(ctx, actor, "interface.forget", "interface", id, ip, map[string]any{
		"interface": iface.Name, "peers": b.Peers, "devices": b.Devices,
	})
	return b, nil
}

// SampleNow снимает дамп интерфейса вне очереди, но не чаще LiveSampleEvery: пока открыта живая
// страница, данные обновляются раз в 5 с, а не раз в 15 (SPEC FR-6.1). Без троттлинга каждая
// вкладка добавляла бы отдельный опрос.
func (h *Hub) SampleNow(ctx context.Context, ifaceID int64) {
	h.mu.Lock()
	// Интерфейс, ещё не попавший в обход, пропускаем: sampleOne записал бы его пиров с нулевым
	// идентификатором, то есть в никуда.
	ref, known := h.ifaces[ifaceID]
	if !known {
		h.mu.Unlock()
		return
	}
	last := h.liveSample[ifaceID]
	if time.Since(last) < LiveSampleEvery {
		h.mu.Unlock()
		return
	}
	h.liveSample[ifaceID] = time.Now()
	h.mu.Unlock()
	if err := h.sampleOne(ctx, ifaceID); err != nil {
		h.Log.Debug("внеочередная выборка", "iface", ref.Name, "err", err)
	}
}

// SampleAllNow — то же для всех известных интерфейсов (дашборд).
func (h *Hub) SampleAllNow(ctx context.Context) {
	for _, id := range h.sweepIDs() {
		h.SampleNow(ctx, id)
	}
}

// housekeeping — почасовая уборка: истёкшие пользователи отключаются (FR-2.5), просроченные
// сессии и содержимое корзины удаляются (FR-2.3, FR-3.4). Без неё корзина растёт вечно,
// а адреса удалённых устройств не возвращаются в пул.
func (h *Hub) housekeeping(ctx context.Context) error {
	expired, err := h.Store.ExpireUsers(ctx)
	if err != nil {
		return err
	}
	for _, id := range expired {
		u, err := h.Store.UserByID(ctx, id)
		if err != nil {
			continue
		}
		if err := h.applyUserDevices(ctx, id); err != nil {
			h.Log.Warn("снятие пиров по истечении срока", "user", u.Name, "err", err)
		}
		h.event(ctx, "user_expired", "warn", 0, 0, fmt.Sprintf("у пользователя «%s» истёк срок — доступ закрыт", u.Name))
		h.audit(ctx, store.ActorSystem, "user.expired", "user", id, "", map[string]any{"name": u.Name})
	}
	if n, err := h.Store.PurgeSessions(ctx); err != nil {
		return err
	} else if n > 0 {
		h.Log.Info("просроченные сессии удалены", "n", n)
	}
	users, devices, err := h.Store.PurgeDeleted(ctx, store.PurgeAfter)
	if err != nil {
		return err
	}
	if users+devices > 0 {
		h.Log.Info("корзина очищена", "users", users, "devices", devices)
		h.event(ctx, "purge", "info", 0, 0, fmt.Sprintf("окончательно удалено: пользователей %d, устройств %d", users, devices))
	}
	return h.vacuumIfDue(ctx)
}

// vacuumIfDue раз в неделю ужимает файл БД (FR-6.8): после ретеншна страницы освобождаются,
// но файл сам не уменьшается. Отметка о последнем прогоне живёт в настройках.
func (h *Hub) vacuumIfDue(ctx context.Context) error {
	const key = "vacuum_at"
	last, err := h.Store.Setting(ctx, key)
	if err != nil {
		return err
	}
	if last != "" {
		ts, err := strconv.ParseInt(last, 10, 64)
		if err == nil && time.Since(time.Unix(ts, 0)) < 7*24*time.Hour {
			return nil
		}
	}
	before, _ := h.Store.DBSize(ctx)
	started := time.Now()
	if err := h.Store.Vacuum(ctx); err != nil {
		return err
	}
	after, _ := h.Store.DBSize(ctx)
	h.Log.Info("база ужата", "было", before, "стало", after, "заняло", time.Since(started).Round(time.Millisecond))
	return h.Store.SetSetting(ctx, key, strconv.FormatInt(time.Now().Unix(), 10))
}

// ensureEndpoint даёт интерфейсу вариант endpoint по умолчанию: имя хоста и порт из конфига.
// Без него панель не соберёт ни одного клиентского конфига, а угадать внешнее имя она не может —
// администратор поправит его в карточке интерфейса.
func (h *Hub) ensureEndpoint(ctx context.Context, srv *Server, id int64, info node.InterfaceInfo) {
	ifaces, err := h.Store.Interfaces(ctx, srv.ID)
	if err != nil {
		return
	}
	for _, iface := range ifaces {
		if iface.ID != id || len(iface.Endpoints) > 0 || info.ListenPort == 0 {
			continue
		}
		host := ""
		if hi, err := srv.Agent.HostInfo(ctx); err == nil {
			host = hi.Hostname
		}
		if host == "" {
			return
		}
		if err := h.Store.SetEndpoints(ctx, id, []store.Endpoint{{Label: "основной", Host: host, Port: info.ListenPort, Primary: true}}); err != nil {
			h.Log.Warn("endpoint по умолчанию", "iface", info.Name, "err", err)
			return
		}
		h.Log.Info("интерфейсу задан endpoint по умолчанию", "iface", info.Name, "endpoint", host)
		h.Store.AddEvent(ctx, store.Event{Kind: "iface_endpoint", Severity: "warn", ServerID: srv.ID, InterfaceID: id,
			Message: "интерфейсу " + info.Name + " задан endpoint по умолчанию " + host + " — проверьте, то ли имя видят клиенты"})
	}
}

// SetEndpoints сохраняет варианты endpoint интерфейса из админки.
func (h *Hub) SetEndpoints(ctx context.Context, ifaceID int64, eps []store.Endpoint, actor, ip string) error {
	if err := h.Store.SetEndpoints(ctx, ifaceID, eps); err != nil {
		return err
	}
	iface, err := h.Interface(ctx, ifaceID)
	if err != nil {
		return err
	}
	labels := make([]string, 0, len(eps))
	for _, e := range eps {
		labels = append(labels, e.Label)
	}
	h.audit(ctx, actor, "interface.endpoints", "interface", ifaceID, ip, map[string]any{"interface": iface.Name, "endpoints": strings.Join(labels, ", ")})
	return nil
}

// SetInterfaceDefaults сохраняет умолчания, из которых собирается клиентский конфиг. Записи на
// сам интерфейс тут нет и быть не может: DNS, keepalive и AllowedIPs живут только в [Peer] у
// клиента, а `[Interface]` на сервере панель не трогает. Смена умолчаний меняет то, что человек
// получит при следующей выдаче (FR-4.1) — уже скачанные файлы и переопределения устройств
// остаются как были.
func (h *Hub) SetInterfaceDefaults(ctx context.Context, ifaceID int64, dns string, keepalive int, allowedIPs string, actor, ip string) error {
	if err := h.Store.SetInterfaceDefaults(ctx, ifaceID, dns, keepalive, allowedIPs); err != nil {
		return err
	}
	iface, err := h.Interface(ctx, ifaceID)
	if err != nil {
		return err
	}
	h.audit(ctx, actor, "interface.defaults", "interface", ifaceID, ip, map[string]any{
		"interface": iface.Name, "dns": iface.DefaultDNS, "keepalive": iface.DefaultKeepalive, "allowed_ips": iface.DefaultAllowedIPs,
	})
	return nil
}

// sweepIDs — идентификаторы интерфейсов, которые панель обходит.
func (h *Hub) sweepIDs() []int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]int64, 0, len(h.ifaces))
	for id := range h.ifaces {
		out = append(out, id)
	}
	return out
}

// sampleAll снимает дамп каждого интерфейса и записывает дельты.
func (h *Hub) sampleAll(ctx context.Context) error {
	ids := h.sweepIDs()
	var firstErr error
	for _, id := range ids {
		if err := h.sampleOne(ctx, id); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", h.ifaceName(id), err)
		}
	}
	if firstErr == nil {
		h.mu.Lock()
		h.lastSample = time.Now()
		h.lastErr = ""
		h.mu.Unlock()
	}
	h.noteSampleResult(ctx, firstErr)
	return firstErr
}

// ifaceName — имя интерфейса из обхода; для сообщений.
func (h *Hub) ifaceName(id int64) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.ifaces[id].Name
}

func (h *Hub) sampleOne(ctx context.Context, id int64) error {
	h.mu.Lock()
	ref := h.ifaces[id]
	name, serverID := ref.Name, ref.ServerID
	since := h.appliedAt[id]
	h.mu.Unlock()
	if name == "" {
		return nil // интерфейс уже ушёл из обхода
	}
	// Курсор живёт в памяти, а панель перезапускается: после рестарта он пуст, и узел отдаёт
	// весь свой суточный буфер одним ответом — на живом узле это были 12 МБ, которые не пролезали в
	// клиента и роняли выборку насовсем (буфер растёт, ответ ещё больше, и так по кругу).
	// Восстанавливаем курсор из БД: докуда разобрано, видно по времени последней выборки.
	if since.IsZero() {
		if at, err := h.Store.LastSampleAt(ctx, id); err == nil && !at.IsZero() {
			since = at
			h.mu.Lock()
			h.appliedAt[id] = at
			h.mu.Unlock()
		}
	}
	agent, err := h.Agent(serverID)
	if err != nil {
		return err
	}
	// Удалённый узел копит выборки сам: забираем всё, что прошло мимо, пока связь была
	// порвана. Локальный буфера не ведёт и вернёт пустой список — тогда работаем дампом.
	buffered, err := agent.Samples(ctx, since, 0)
	if err != nil {
		return err
	}
	applied := 0
	var oldest time.Time
	for _, s := range buffered {
		if s.Interface != name {
			continue
		}
		if err := h.applySample(ctx, serverID, id, name, s.At, s.Peers, s.InConf); err != nil {
			return err
		}
		applied++
		if oldest.IsZero() || s.At.Before(oldest) {
			oldest = s.At
		}
		h.mu.Lock()
		h.appliedAt[id] = s.At
		h.mu.Unlock()
	}
	if applied > 1 {
		h.Log.Debug("добраны пропущенные выборки", "iface", name, "n", applied)
	}
	if applied > 0 {
		// Догнанные выборки ложатся своим временем — часто глубже окна обычного rollup (2 часа).
		// Без пересчёта агрегатов графики показали бы на этом месте пустоту, хотя записи есть.
		if window := time.Since(oldest) + 5*time.Minute; window > rollupEvery {
			if window > maxRollup {
				window = maxRollup
			}
			if err := h.Store.Rollup(ctx, window); err != nil {
				return err
			}
		}
		return nil
	}

	_, peers, err := agent.Dump(ctx, name)
	if err != nil {
		return err
	}
	var inConf []string
	if confPeers, err := agent.ConfPeers(ctx, name); err == nil {
		for _, p := range confPeers {
			inConf = append(inConf, p.PublicKey)
		}
	}
	return h.applySample(ctx, serverID, id, name, time.Now(), peers, inConf)
}

// applySample записывает одну выборку интерфейса: дельты, состояния, события. Время берётся
// из самой выборки — так буфер узла ложится в историю там, где он был снят, а не «сейчас».
func (h *Hub) applySample(ctx context.Context, serverID, ifaceID int64, name string, at time.Time, peers []awg.PeerDump, inConf []string) error {
	inConfSet := make(map[string]bool, len(inConf))
	for _, k := range inConf {
		inConfSet[k] = true
	}
	samples := make([]store.PeerSample, 0, len(peers))
	for _, p := range peers {
		samples = append(samples, store.PeerSample{PublicKey: p.PublicKey, AllowedIPs: strings.Join(p.AllowedIPs, ", "),
			HasPSK: p.HasPSK, InConf: inConfSet[p.PublicKey], Endpoint: p.Endpoint, LastHandshake: p.LatestHandshake, Rx: p.Rx, Tx: p.Tx})
	}
	res, err := h.Store.ApplySample(ctx, ifaceID, at, samples, OnlineThreshold)
	if err != nil {
		return err
	}
	h.mu.Lock()
	h.peersNow[ifaceID] = res.Peers
	h.onlineNow[ifaceID] = res.Online
	h.mu.Unlock()
	h.noteFirstOnline(ctx, serverID, ifaceID, res.FirstOnline)
	if res.Resets > 0 {
		h.Store.AddEvent(ctx, store.Event{Kind: "counters_reset", ServerID: serverID, InterfaceID: ifaceID,
			Message: fmt.Sprintf("%s: сброс счётчиков у %d пиров (рестарт интерфейса или пересоздание пира)", name, res.Resets)})
	}
	return nil
}

// metrics пишет минутную метрику каждого хоста парка.
func (h *Hub) metrics(ctx context.Context) error {
	var firstErr error
	for _, srv := range h.servers.all() {
		if err := h.metricsOf(ctx, srv); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", srv.Slug, err)
		}
	}
	return firstErr
}

func (h *Hub) metricsOf(ctx context.Context, srv *Server) error {
	s, err := srv.Agent.HostMetrics(ctx)
	if err != nil {
		return err
	}
	if !s.Supported {
		return nil
	}
	online := 0
	h.mu.Lock()
	for id, n := range h.onlineNow {
		if h.ifaces[id].ServerID == srv.ID {
			online += n
		}
	}
	h.mu.Unlock()
	h.checkThresholds(ctx, srv, s)
	return h.Store.InsertHostMetric(ctx, store.HostMetric{ServerID: srv.ID, TS: s.At, CPU: s.CPUPercent, MemUsed: s.MemUsed, MemTotal: s.MemTotal, SwapUsed: s.SwapUsed, SwapTotal: s.SwapTotal,
		DiskUsed: s.DiskUsed, DiskTotal: s.DiskTotal, Load1: s.Load1, NetRxBps: uint64(s.NetRxBps), NetTxBps: uint64(s.NetTxBps), NetRxBytes: s.NetRxBytes, NetTxBytes: s.NetTxBytes, PeersOnline: online})
}

// ForeignManager — последний известный активный чужой менеджер пиров (пусто, если чисто).
// Значение обновляется сверкой раз в 5 минут: спрашивать systemctl на каждый показ страницы дорого.
func (h *Hub) ForeignManager() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.foreign
}

// ForeignManagerOf — чужой менеджер пиров на конкретном сервере парка.
func (h *Hub) ForeignManagerOf(serverID int64) string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.foreignBy[serverID]
}

// verifyAll сверяет обфускацию по каждому интерфейсу каждого узла; смена результата — событие.
func (h *Hub) verifyAll(ctx context.Context) error {
	var firstErr error
	for _, srv := range h.servers.all() {
		fm := srv.Agent.ForeignManagerActive(ctx)
		h.mu.Lock()
		if srv.Local {
			h.foreign = fm
		}
		h.foreignBy[srv.ID] = fm
		ids := make([]int64, 0, len(h.ifaces))
		names := make(map[int64]string, len(h.ifaces))
		for id, ref := range h.ifaces {
			if ref.ServerID == srv.ID {
				ids = append(ids, id)
				names[id] = ref.Name
			}
		}
		h.mu.Unlock()
		for _, id := range ids {
			name := names[id]
			res, err := srv.Agent.Verify(ctx, name)
			if err != nil {
				if firstErr == nil {
					firstErr = fmt.Errorf("verify %s: %w", name, err)
				}
				continue
			}
			h.Store.SetVerify(ctx, id, res.OK, res)
			h.mu.Lock()
			prev, known := h.verifyOK[id]
			h.verifyOK[id] = res.OK
			h.mu.Unlock()
			if (!known && !res.OK) || (known && prev != res.OK) {
				payload, _ := json.Marshal(res.Diffs)
				if res.OK {
					h.Store.AddEvent(ctx, store.Event{Kind: "verify_ok", ServerID: srv.ID, InterfaceID: id, Message: name + ": обфускация снова совпадает 12/12"})
				} else {
					h.Store.AddEvent(ctx, store.Event{Kind: "verify_failed", Severity: "crit", ServerID: srv.ID, InterfaceID: id,
						Message: fmt.Sprintf("%s: обфускация в файле и рантайме расходится (%d/%d)", name, res.Matched, res.Total), Payload: payload})
				}
			}
		}
	}
	return firstErr
}

// PeerState — состояние пира для отображения (SPEC FR-6.2).
// StuckGrowth — рост счётчиков, ниже которого «трафик идёт» считается только keepalive-пакетами.
const StuckGrowth = 2 * 1024

// PeerStateFull различает «офлайн» и «застрял»: хендшейка нет, но счётчики понемногу растут —
// значит клиент шлёт пакеты, а рукопожатие не проходит (обычно NAT оператора). Показывается
// только администратору: пользователю такое различие ничего не даёт (SPEC FR-6.2).
func PeerStateFull(lastHandshake time.Time, growth5m uint64, now time.Time) (label, class string) {
	label, class = PeerState(lastHandshake, now)
	if label == "офлайн" && growth5m > 0 && growth5m < StuckGrowth {
		return "застрял", "warn"
	}
	return label, class
}

func PeerState(lastHandshake time.Time, now time.Time) (label, class string) {
	if lastHandshake.IsZero() {
		return "не подключался", "muted"
	}
	age := now.Sub(lastHandshake)
	switch {
	case age <= OnlineThreshold:
		return "онлайн", "ok"
	case age <= 10*time.Minute:
		return "недавно", "muted"
	default:
		return "офлайн", "muted"
	}
}
