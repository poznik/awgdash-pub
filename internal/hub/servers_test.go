package hub

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/poznik/awgdash-pub/internal/awg"
	"github.com/poznik/awgdash-pub/internal/awgtest"
	"github.com/poznik/awgdash-pub/internal/node"
	"github.com/poznik/awgdash-pub/internal/store"
)

// Реестр узлов: локальный есть всегда, удалённый приезжает из БД и уходит, когда выключен.
func TestServerRegistry(t *testing.T) {
	h, _, _ := testHub(t)
	ctx := context.Background()

	// Локальный узел доступен даже без записи в реестре — на нём работает сам хаб.
	if _, err := h.Agent(h.ServerID); err != nil {
		t.Fatalf("локальный узел недоступен: %v", err)
	}
	if _, err := h.Agent(9999); err == nil {
		t.Fatal("неизвестный сервер выдал агента вместо ошибки")
	}

	srv, err := h.Store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", SSHHost: "kz", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	if srv.Transport != "ssh" || !srv.Enabled || srv.NodePort != 10089 {
		t.Fatalf("узел заведён неверно: %+v", srv)
	}
	if err := h.LoadServers(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Agent(srv.ID); err != nil {
		t.Fatalf("удалённый узел не попал в реестр: %v", err)
	}
	if len(h.Servers()) != 2 {
		t.Fatalf("в реестре %d узлов, ожидалось 2", len(h.Servers()))
	}

	// Выключенный узел перестаёт опрашиваться, но данные остаются.
	if err := h.Store.SetServerEnabled(ctx, srv.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := h.LoadServers(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Agent(srv.ID); err == nil {
		t.Fatal("выключенный узел остался в реестре")
	}
	if _, err := h.Store.ServerBySlug(ctx, "kz"); err != nil {
		t.Fatalf("запись выключенного узла пропала: %v", err)
	}
}

// Локальный сервер удалить нельзя, удалённый — только когда на нём нет интерфейсов.
func TestDeleteServerRules(t *testing.T) {
	h, _, iface := testHub(t)
	ctx := context.Background()
	if err := h.Store.DeleteServer(ctx, h.ServerID); err == nil {
		t.Fatal("локальный сервер удалился")
	}
	if iface.ServerID != h.ServerID {
		t.Fatalf("интерфейс привязан к серверу %d, ожидался %d", iface.ServerID, h.ServerID)
	}

	srv, err := h.Store.AddServer(ctx, store.NewServer{Slug: "kz", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Store.UpsertInterface(ctx, srv.ID, "awg-kz", store.InterfaceFacts{Subnet: "10.30.0.0/24"}); err != nil {
		t.Fatal(err)
	}
	if err := h.Store.DeleteServer(ctx, srv.ID); err == nil {
		t.Fatal("сервер с интерфейсами удалился")
	}
}

// Слаг занят — второй такой же сервер не заводится.
func TestAddServerRejectsDuplicate(t *testing.T) {
	h, _, _ := testHub(t)
	ctx := context.Background()
	if _, err := h.Store.AddServer(ctx, store.NewServer{Slug: "kz", NodePort: 10089}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Store.AddServer(ctx, store.NewServer{Slug: "kz", NodePort: 10090}); err == nil {
		t.Fatal("дубль слага прошёл")
	}
	if _, err := h.Store.AddServer(ctx, store.NewServer{Slug: "ru"}); err == nil {
		t.Fatal("узел без порта прошёл")
	}
}

// bufferAgent — узел с буфером: отдаёт заранее записанные выборки, как удалённый после
// разрыва связи.
type bufferAgent struct {
	Agent
	samples []node.Sample
}

func (a *bufferAgent) Samples(_ context.Context, since time.Time, _ int) ([]node.Sample, error) {
	var out []node.Sample
	for _, s := range a.samples {
		if s.At.After(since) {
			out = append(out, s)
		}
	}
	return out, nil
}

// Хаб раскладывает буфер узла по времени, а не сваливает всё в «сейчас»: история за время
// разрыва связи должна лечь туда, где она была снята (FR-10.4).
func TestHubAppliesBufferedSamples(t *testing.T) {
	h, _, iface := testHub(t)
	ctx := context.Background()

	base := time.Now().Add(-30 * time.Minute).Truncate(time.Second)
	mk := func(at time.Time, rx, tx uint64) node.Sample {
		return node.Sample{At: at, Interface: iface.Name, InConf: []string{awgtest.KeyA},
			Peers: []awg.PeerDump{{PublicKey: awgtest.KeyA, AllowedIPs: []string{"10.20.0.2/32"},
				LatestHandshake: at, Rx: rx, Tx: tx}}}
	}
	agent := &bufferAgent{Agent: LocalAgent{N: h.Node}, samples: []node.Sample{
		mk(base, 1000, 500),
		mk(base.Add(10*time.Minute), 3000, 1500),
		mk(base.Add(20*time.Minute), 6000, 3000),
	}}
	h.servers.put(&Server{ID: h.ServerID, Slug: "de", Local: true, Agent: agent})
	h.mu.Lock()
	h.ifaces[iface.ID] = ifaceRef{Name: iface.Name, ServerID: h.ServerID}
	h.mu.Unlock()

	if err := h.sampleOne(ctx, iface.ID); err != nil {
		t.Fatal(err)
	}
	// Первая выборка задаёт базу для дельт, следующие дают трафик по своим временам.
	peers, err := h.Store.Peers(ctx, iface.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	var peerID int64
	for _, p := range peers {
		if p.PublicKey == awgtest.KeyA {
			peerID = p.ID
		}
	}
	if peerID == 0 {
		t.Fatal("пир из буфера не появился в базе")
	}
	points, err := h.Store.PeerSeries(ctx, []int64{peerID}, h.ServerID, base.Add(-time.Minute), 5*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var buckets int
	var total uint64
	for _, p := range points {
		if p.Rx > 0 {
			buckets++
			total += p.Rx
		}
	}
	if buckets < 2 {
		t.Fatalf("трафик лёг в %d корзин — буфер свалили в одну точку", buckets)
	}
	if total != 5000 {
		t.Fatalf("принято %d байт, ожидалось 5000 (дельты 2000 и 3000)", total)
	}

	// Повторный вызов ничего не добирает: отметка «до какого момента разобрано» работает.
	before := total
	if err := h.sampleOne(ctx, iface.ID); err != nil {
		t.Fatal(err)
	}
	points, _ = h.Store.PeerSeries(ctx, []int64{peerID}, h.ServerID, base.Add(-time.Minute), 5*time.Minute)
	total = 0
	for _, p := range points {
		total += p.Rx
	}
	if total != before {
		t.Fatalf("после повтора стало %d байт вместо %d — выборки применились дважды", total, before)
	}
}

// Догнанные выборки могут быть старше окна обычного rollup (2 часа). Графики читают агрегаты,
// поэтому после добора хаб пересчитывает их на всю глубину буфера — иначе в истории осталась бы
// дыра ровно там, где связь порвалась, хотя записи в базе есть.
func TestHubRollsUpBackfilledHistory(t *testing.T) {
	h, _, iface := testHub(t)
	ctx := context.Background()

	// Связи не было пять часов; узел отдаёт свой буфер разом.
	base := time.Now().Add(-5 * time.Hour).Truncate(time.Second)
	mk := func(at time.Time, rx, tx uint64) node.Sample {
		return node.Sample{At: at, Interface: iface.Name, InConf: []string{awgtest.KeyA},
			Peers: []awg.PeerDump{{PublicKey: awgtest.KeyA, AllowedIPs: []string{"10.20.0.2/32"},
				LatestHandshake: at, Rx: rx, Tx: tx}}}
	}
	var samples []node.Sample
	for i := 0; i <= 8; i++ { // каждые полчаса, пять часов подряд
		samples = append(samples, mk(base.Add(time.Duration(i)*30*time.Minute), uint64(1000*(i+1)), uint64(100*(i+1))))
	}
	agent := &bufferAgent{Agent: LocalAgent{N: h.Node}, samples: samples}
	h.servers.put(&Server{ID: h.ServerID, Slug: "de", Local: true, Agent: agent})
	h.mu.Lock()
	h.ifaces[iface.ID] = ifaceRef{Name: iface.Name, ServerID: h.ServerID}
	h.mu.Unlock()

	if err := h.sampleOne(ctx, iface.ID); err != nil {
		t.Fatal(err)
	}
	peers, err := h.Store.Peers(ctx, iface.ID, false)
	if err != nil {
		t.Fatal(err)
	}
	var peerID int64
	for _, p := range peers {
		if p.PublicKey == awgtest.KeyA {
			peerID = p.ID
		}
	}
	if peerID == 0 {
		t.Fatal("пир из буфера не появился в базе")
	}

	// Суточный график: получасовая корзина, ряд собирается из пятиминуток.
	points, err := h.Store.PeerSeries(ctx, []int64{peerID}, h.ServerID, time.Now().Add(-24*time.Hour), 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var buckets int
	var total uint64
	for _, p := range points {
		if p.Rx > 0 {
			buckets++
			total += p.Rx
		}
	}
	if buckets < 4 {
		t.Fatalf("догнанная история попала в %d корзин — агрегаты не пересчитаны на глубину буфера", buckets)
	}
	// Дельты между восемью выборками по 1000 байт — 8000 всего.
	if total != 8000 {
		t.Fatalf("в ряду %d байт, ожидалось 8000", total)
	}

	// Недельный ряд идёт по часовым агрегатам — там та же история должна быть видна.
	week, err := h.Store.PeerSeries(ctx, []int64{peerID}, h.ServerID, time.Now().Add(-7*24*time.Hour), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var weekTotal uint64
	for _, p := range week {
		weekTotal += p.Rx
	}
	if weekTotal != 8000 {
		t.Fatalf("в недельном ряду %d байт, ожидалось 8000 — часовые агрегаты не пересчитаны", weekTotal)
	}
}

// Состав парка меняется на ходу: вывод снимает узел с опроса сразу, возврат возвращает,
// а изменение мимо хаба (CLI — другой процесс, та же БД) догоняет сверка реестра (FR-10.8).
func TestFleetChangesReachRegistryWithoutRestart(t *testing.T) {
	h, _, _ := testHub(t)
	ctx := context.Background()
	srv, err := h.Store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", SSHHost: "kz", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.LoadServers(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Agent(srv.ID); err != nil {
		t.Fatalf("удалённый узел не попал в реестр: %v", err)
	}

	// Вывод из панели действует сразу: опрашивать машину, которой нет, незачем.
	if err := h.RetireServer(ctx, srv.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Agent(srv.ID); err == nil {
		t.Fatal("выведенный сервер остался в опросе")
	}

	// Возврат — тоже сразу: ради этого всё и затевалось.
	if err := h.ReturnServer(ctx, srv.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Agent(srv.ID); err != nil {
		t.Fatalf("вернувшийся сервер не взят в работу: %v", err)
	}

	// Название меняется у узла, который уже в работе: сверка обновляет запись, не трогая связь.
	if err := h.Store.SetServerTitle(ctx, srv.ID, "Казахстан-2"); err != nil {
		t.Fatal(err)
	}
	if err := h.LoadServers(ctx); err != nil {
		t.Fatal(err)
	}
	if title := registryTitle(h, srv.ID); title != "Казахстан-2" {
		t.Fatalf("в реестре имя %q, ожидалось «Казахстан-2»", title)
	}

	// Интерфейс ушедшего сервера не должен остаться в обходе: живой узел его отдаёт при
	// обнаружении, здесь кладём руками — до настоящего kz из теста не дотянуться.
	kzIf, err := h.Store.UpsertInterface(ctx, srv.ID, "awg-kz", store.InterfaceFacts{Subnet: "10.30.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.ifaces[kzIf] = ifaceRef{Name: "awg-kz", ServerID: srv.ID}
	h.mu.Unlock()

	// Выключение мимо хаба: до сверки узел ещё в реестре, после — уже нет.
	if err := h.Store.SetServerEnabled(ctx, srv.ID, false); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Agent(srv.ID); err != nil {
		t.Fatal("узел ушёл из реестра сам — тест проверяет не то")
	}
	if err := h.LoadServers(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Agent(srv.ID); err == nil {
		t.Fatal("выключенный узел остался в реестре после сверки")
	}
	// Выборка больше о него не спотыкается: иначе через две минуты панель объявила бы
	// упавшим узел, который выключили нарочно (FR-10.6).
	if err := h.sampleAll(ctx); err != nil {
		t.Fatalf("выборка спотыкается об ушедший сервер: %v", err)
	}
	h.mu.Lock()
	_, stillThere := h.ifaces[kzIf]
	h.mu.Unlock()
	if stillThere {
		t.Fatal("интерфейс ушедшего сервера остался в обходе")
	}

	// Удаление уносит и запись, и место в реестре; локальный узел остаётся на месте.
	if err := h.Store.SetServerEnabled(ctx, srv.ID, true); err != nil {
		t.Fatal(err)
	}
	if err := h.RetireServer(ctx, srv.ID); err != nil {
		t.Fatal(err)
	}
	if err := h.DeleteServer(ctx, srv.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.Agent(srv.ID); err == nil {
		t.Fatal("удалённый сервер остался в реестре")
	}
	if len(h.Servers()) != 1 {
		t.Fatalf("в реестре %d узлов, ожидался один локальный", len(h.Servers()))
	}
}

func registryTitle(h *Hub, id int64) string {
	for _, srv := range h.Servers() {
		if srv.ID == id {
			return srv.Title
		}
	}
	return ""
}

// sinceAgent запоминает, с какого момента у него просили выборки.
type sinceAgent struct {
	Agent
	asked []time.Time
}

func (a *sinceAgent) Samples(_ context.Context, since time.Time, _ int) ([]node.Sample, error) {
	a.asked = append(a.asked, since)
	return nil, nil
}

// После перезапуска панели курсор восстанавливается из БД. Пока он жил только в памяти, свежий
// хаб просил у узла весь суточный буфер: на живом парке это 12 МБ в одном ответе, которые не
// пролезали в клиента — выборки падали насовсем, и панель показывала «0 в туннеле» при
// работающем туннеле.
func TestSampleCursorSurvivesRestart(t *testing.T) {
	h, _, iface := testHub(t)
	ctx := context.Background()

	at := time.Now().Add(-3 * time.Minute).Truncate(time.Second)
	agent := &bufferAgent{Agent: LocalAgent{N: h.Node}, samples: []node.Sample{{
		At: at, Interface: iface.Name, InConf: []string{awgtest.KeyA},
		Peers: []awg.PeerDump{{PublicKey: awgtest.KeyA, AllowedIPs: []string{"10.20.0.2/32"}, LatestHandshake: at, Rx: 10, Tx: 20}},
	}}}
	h.servers.put(&Server{ID: h.ServerID, Slug: "de", Local: true, Agent: agent})
	h.mu.Lock()
	h.ifaces[iface.ID] = ifaceRef{Name: iface.Name, ServerID: h.ServerID}
	h.mu.Unlock()
	if err := h.sampleOne(ctx, iface.ID); err != nil {
		t.Fatal(err)
	}

	// Свежий хаб на той же БД — как после перезапуска службы: память пуста.
	restarted := New(h.Cfg, h.Store, h.Node, h.Log)
	restarted.ServerID = h.ServerID
	probe := &sinceAgent{Agent: LocalAgent{N: h.Node}}
	restarted.servers.put(&Server{ID: h.ServerID, Slug: "de", Local: true, Agent: probe})
	restarted.mu.Lock()
	restarted.ifaces[iface.ID] = ifaceRef{Name: iface.Name, ServerID: h.ServerID}
	restarted.mu.Unlock()
	if err := restarted.sampleOne(ctx, iface.ID); err != nil {
		t.Fatal(err)
	}
	if len(probe.asked) != 1 {
		t.Fatalf("узел опрошен %d раз", len(probe.asked))
	}
	if probe.asked[0].IsZero() {
		t.Fatal("после перезапуска панель просит весь буфер узла заново")
	}
	if !probe.asked[0].Equal(at) {
		t.Fatalf("курсор восстановлен неверно: %v вместо %v", probe.asked[0], at)
	}
}

// Интерфейс, снятый с сервера, панель замечает сама: конфига нет — запись помечается «пропал»,
// из обхода уходит (иначе выборка каждые 15 с спотыкается о несуществующий интерфейс), а
// убирает её человек. Вернувшийся интерфейс оживает без вмешательства.
func TestGoneInterfaceNoticedAndForgotten(t *testing.T) {
	h, _, iface := testHub(t)
	ctx := context.Background()
	conf := h.Node.ConfPath(iface.Name)

	if err := h.discover(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ := h.Interface(ctx, iface.ID); got.Status != "ok" {
		t.Fatalf("живой интерфейс в статусе %q", got.Status)
	}
	// Пока интерфейс на месте, убрать его из панели нельзя: для этого есть режим observe.
	if _, err := h.ForgetInterface(ctx, iface.ID, store.ActorAdmin, ""); err == nil {
		t.Fatal("живой интерфейс убрали из панели")
	}

	saved, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(conf); err != nil {
		t.Fatal(err)
	}
	if err := h.discover(ctx); err != nil {
		t.Fatal(err)
	}
	got, err := h.Interface(ctx, iface.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != store.StatusGone || got.UnitActive {
		t.Fatalf("пропавший интерфейс: статус %q, юнит %v", got.Status, got.UnitActive)
	}
	h.mu.Lock()
	_, inSweep := h.ifaces[iface.ID]
	h.mu.Unlock()
	if inSweep {
		t.Fatal("пропавший интерфейс остался в обходе — выборка будет спотыкаться о него")
	}
	events, _ := h.Store.Events(ctx, 20)
	gone := 0
	for _, e := range events {
		if e.Kind == "iface_gone" {
			gone++
		}
	}
	if gone != 1 {
		t.Fatalf("событий о пропаже: %d", gone)
	}

	// Вернулся — снова живой, и никаких следов «пропал».
	if err := os.WriteFile(conf, saved, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := h.discover(ctx); err != nil {
		t.Fatal(err)
	}
	if got, _ = h.Interface(ctx, iface.ID); got.Status != "ok" {
		t.Fatalf("вернувшийся интерфейс в статусе %q", got.Status)
	}

	// Снова снимаем — и на этот раз убираем из панели вместе с устройством.
	uid, _, err := h.Store.CreateUser(ctx, store.User{Name: "Хозяин", MaxDevices: 5, DefaultInterfaceID: iface.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.CreateDevice(ctx, NewDevice{UserID: uid, InterfaceID: iface.ID, Name: "Телефон"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(conf); err != nil {
		t.Fatal(err)
	}
	if err := h.discover(ctx); err != nil {
		t.Fatal(err)
	}
	b, err := h.ForgetInterface(ctx, iface.ID, store.ActorAdmin, "")
	if err != nil {
		t.Fatal(err)
	}
	if b.Devices != 1 {
		t.Fatalf("в отчёте об удалении устройств %d, ожидалось 1", b.Devices)
	}
	if _, err := h.Interface(ctx, iface.ID); err == nil {
		t.Fatal("интерфейс остался в панели после «убрать»")
	}
	if devs, _ := h.Store.DevicesByUser(ctx, uid); len(devs) != 0 {
		t.Fatalf("устройства на убранном интерфейсе остались: %d", len(devs))
	}
	// Пользователь остаётся — у него просто нет устройств на этой машине.
	if _, err := h.Store.UserByID(ctx, uid); err != nil {
		t.Fatalf("пользователь пропал вместе с интерфейсом: %v", err)
	}
}

// Обход ключуется по интерфейсу, а не по имени: одноимённые интерфейсы на разных машинах
// парка должны опрашиваться и сверяться оба. По имени карта оставляла один из них, и второй
// молча выпадал из выборок — на живом парке такой интерфейс не опрашивался полтора часа.
func TestSweepKeepsSameNamedInterfaces(t *testing.T) {
	h, _, iface := testHub(t)
	ctx := context.Background()
	if err := h.discover(ctx); err != nil {
		t.Fatal(err)
	}
	kz, err := h.Store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", SSHHost: "kz", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	twin, err := h.Store.UpsertInterface(ctx, kz.ID, iface.Name, store.InterfaceFacts{Subnet: "10.30.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	h.ifaces[twin] = ifaceRef{Name: iface.Name, ServerID: kz.ID}
	h.mu.Unlock()

	ids := h.sweepIDs()
	seen := map[int64]bool{}
	for _, id := range ids {
		seen[id] = true
	}
	if !seen[iface.ID] || !seen[twin] {
		t.Fatalf("в обходе %d интерфейсов, однофамильцы потерялись: %v", len(ids), ids)
	}
	// Пропажа одного из них не уносит второго: имя у них общее, машина — разная.
	h.mu.Lock()
	h.dropIface(twin)
	h.mu.Unlock()
	if _, still := h.ifaces[iface.ID]; !still {
		t.Fatal("вместе с однофамильцем из обхода ушёл живой интерфейс")
	}
}

// Наблюдаемый интерфейс не место посадки: панель на нём пиров не пишет, и человек получил бы
// конфиг, который не подключается. В выборе его нет ни у админа, ни в портале (FR-3.1, FR-5.2).
func TestIfaceChoicesSkipObserved(t *testing.T) {
	ctx := context.Background()
	h, _, iface := testHub(t)

	kz, err := h.Store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", SSHHost: "kz", NodePort: 10089})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Store.UpsertInterface(ctx, kz.ID, "awg-hub", store.InterfaceFacts{Subnet: "10.100.0.0/30"}); err != nil {
		t.Fatal(err)
	}

	// Пока панель ничем не управляет, сажать устройство некуда — и это отдельная беда, не
	// пустой парк: сказать о ней надо своими словами.
	if _, err := h.DefaultInterface(ctx); !errors.Is(err, ErrNoOwnInterfaces) {
		t.Fatalf("умолчание при парке из наблюдаемых: %v", err)
	}
	if list, err := h.IfaceChoices(ctx, nil); err != nil || len(list) != 0 {
		t.Fatalf("наблюдаемые попали в выбор: %+v (%v)", list, err)
	}
	if list, err := h.AllIfaceChoices(ctx, nil); err != nil || len(list) != 2 {
		t.Fatalf("весь парк = %+v (%v), ожидались оба интерфейса", list, err)
	}

	own(t, h, iface)
	list, err := h.IfaceChoices(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 1 || list[0].InterfaceID != iface.ID {
		t.Fatalf("в выборе %+v, ожидался только управляемый %s", list, iface.Name)
	}
	def, err := h.DefaultInterface(ctx)
	if err != nil || def != iface.ID {
		t.Fatalf("умолчание = %d (%v), ожидался %d", def, err, iface.ID)
	}
}
