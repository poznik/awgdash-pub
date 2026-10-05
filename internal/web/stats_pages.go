package web

import (
	"context"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/store"
)

// deviceData — карточка устройства: состояние, итоги, история (SPEC FR-6.5).
type deviceData struct {
	Base
	Device    store.Device
	User      store.User
	Interface store.Interface
	Server    store.Server
	Flag      string
	Totals    store.Totals
	Chart     Chart
	Days      []store.Day
	Speed     store.Speed
	State     string
	StateCls  string
	// Say — вывод о состоянии словами; Level — его цвет (PLAN-UI §1.4).
	Say       string
	Level     string
	Range     chartRange
	Ranges    []chartRange
	RangeBase string
	// Owners — кому можно передать это устройство (FR-3.9).
	Owners []store.UserOption
	// Hints — что подставит панель, если переопределение оставить пустым.
	Hints ifaceHints
}

func (s *Server) devicePage(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	id := atoi64(r.PathValue("id"))
	dev, err := s.Hub.Store.DeviceByID(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	d := deviceData{Base: s.base(r, &sc, dev.Name), Device: dev,
		Range: rangeOf(r.URL.Query().Get("range")), Ranges: chartRanges, RangeBase: "/devices/" + itoa(id)}
	d.Section = "users"
	d.User, _ = s.Hub.Store.UserByID(ctx, dev.UserID)
	d.Interface, _ = s.Hub.Interface(ctx, dev.InterfaceID)
	d.Hints = hintsOfIface(d.Interface)
	if dev.DeletedAt.IsZero() {
		d.Owners, _ = s.Hub.Store.UserOptions(ctx)
	}
	if srv, err := s.Hub.Store.ServerByID(ctx, d.Interface.ServerID); err == nil {
		d.Server, d.Flag = srv, srv.Flag()
		d.Device.ServerRetired = srv.Retired()
	}

	peers, err := s.Hub.Store.PeerIDsOf(ctx, []int64{id})
	if err != nil {
		s.fail(w, err)
		return
	}
	if d.Totals, err = s.Hub.Store.PeerTotals(ctx, peers); err != nil {
		s.fail(w, err)
		return
	}
	points, err := s.Hub.Store.PeerSeries(ctx, peers, s.Hub.ServerID, d.Range.Since, d.Range.Bucket)
	if err != nil {
		s.fail(w, err)
		return
	}
	d.Chart = s.buildChart(points, d.Range.Bucket, 480, 120, unitBytes, 1)
	d.Days, _ = s.Hub.Store.PeerDays(ctx, peers, time.Now().Add(-30*24*time.Hour), s.TZ)
	d.Speed, _ = s.Hub.Store.PeerSpeed(ctx, peers, time.Minute)
	growth, _ := s.Hub.Store.PeerGrowth(ctx, peers, 5*time.Minute)
	var g uint64
	for _, v := range growth {
		g += v
	}
	// Когда рукопожатия нет, страница называет день последнего трафика: он переживает
	// перезапуск интерфейса, а рукопожатие — нет.
	var lastSeen time.Time
	if last, err := s.Hub.Store.LastTrafficAt(ctx, peers); err == nil {
		for _, at := range last {
			if at.After(lastSeen) {
				lastSeen = at
			}
		}
	}
	d.State, d.StateCls = hub.PeerStateFull(dev.LastHandshake, g, time.Now())
	d.Say, d.Level = s.deviceSay(dev, d.Interface.UnitActive, g, lastSeen)
	s.render(w, "device.html", d)
}

// interfaceNow — сводка «сейчас» по интерфейсу (FR-6.4).
type interfaceNow struct {
	Speed store.Speed
	Top   []topDevice
}

type topDevice struct {
	Name   string
	User   string
	RxBps  uint64
	TxBps  uint64
	Online bool
}

// fillNow добирает скорость интерфейса и тройку самых активных устройств.
func (s *Server) fillNow(ctx context.Context, det *interfaceDetail) {
	peers := make([]int64, 0, len(det.Peers))
	for _, p := range det.Peers {
		peers = append(peers, p.ID)
	}
	det.Now.Speed, _ = s.Hub.Store.PeerSpeed(ctx, peers, time.Minute)
	// Скорости берутся одной выборкой: запрос на каждого пира стоил 600 запросов и 130 мс
	// на парке приёмки — мимо бюджета §7.1.
	perPeer, _ := s.Hub.Store.PeerSpeeds(ctx, peers, time.Minute)
	for _, p := range det.Peers {
		sp, ok := perPeer[p.ID]
		if !ok || (sp.RxBps == 0 && sp.TxBps == 0) {
			continue
		}
		name := p.Device
		if name == "" {
			name = shortKey(p.PublicKey)
		}
		online, _ := hub.PeerState(p.LastHandshake, time.Now())
		det.Now.Top = append(det.Now.Top, topDevice{Name: name, User: p.User, RxBps: sp.RxBps, TxBps: sp.TxBps, Online: online == "онлайн"})
	}
	sort.Slice(det.Now.Top, func(a, b int) bool {
		return det.Now.Top[a].RxBps+det.Now.Top[a].TxBps > det.Now.Top[b].RxBps+det.Now.Top[b].TxBps
	})
	if len(det.Now.Top) > 5 {
		det.Now.Top = det.Now.Top[:5]
	}
}

// serverData — страница сервера: текущие метрики и сутки истории с порогами (FR-7.2).
type serverData struct {
	Base
	Server   store.Server
	Servers  []serverTab // переключатель серверов парка
	Flag     string
	Ifaces   []ifaceCard
	Remote   bool // узел на другой машине: у него нет базы панели
	Metric   store.HostMetric
	CPU      Chart
	Mem      Chart
	Net      Chart
	DiskPct  int
	MemPct   int
	LoadWarn bool
	DBSize   uint64
	Peers    int
	Online   int
	Totals   store.Totals
	// Уровень и фраза — те же, что на карточке в парке: сервер выглядит одинаково везде.
	Level, LevelWord            string
	Say                         string
	CPUPct                      int
	CPULvl, MemLevel, DiskLevel string
	Notify                      store.NotifyConfig
	// Left — что привязано к серверу: показывается перед выводом и удалением (FR-10.7).
	Left store.ServerBelongings
}

// serverTab — ссылка на другой сервер парка в шапке страницы.
type serverTab struct {
	Slug    string
	Title   string
	Flag    string
	Country string
	Current bool
}

func (s *Server) serverPage(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	servers, err := s.Hub.Store.Servers(ctx)
	if err != nil || len(servers) == 0 {
		s.fail(w, err)
		return
	}
	// Без слага показываем сервер панели: с него смотрят чаще всего.
	slug := r.PathValue("slug")
	current := servers[0]
	for _, srv := range servers {
		if srv.Local() && slug == "" {
			current = srv
		}
		if slug != "" && strings.EqualFold(srv.Slug, slug) {
			current = srv
		}
	}
	if slug != "" && !strings.EqualFold(current.Slug, slug) {
		http.NotFound(w, r)
		return
	}

	d := serverData{Base: s.base(r, &sc, current.Title), Server: current, Flag: current.Flag(), Remote: !current.Local()}
	d.Section = "dashboard"
	for _, srv := range servers {
		d.Servers = append(d.Servers, serverTab{Slug: srv.Slug, Title: srv.Title, Flag: srv.Flag(),
			Country: srv.CountryOrGuess(), Current: srv.ID == current.ID})
	}
	metrics, err := s.Hub.Store.HostMetrics(ctx, d.Server.ID, time.Now().Add(-24*time.Hour))
	if err != nil {
		s.fail(w, err)
		return
	}
	if len(metrics) > 0 {
		d.Metric = metrics[len(metrics)-1]
	}
	// Метрики укладываются в те же графики, что и трафик: одна и та же разметка на все ряды.
	cpu := make([]store.Point, 0, len(metrics))
	mem := make([]store.Point, 0, len(metrics))
	net := make([]store.Point, 0, len(metrics))
	for _, m := range metrics {
		cpu = append(cpu, store.Point{TS: m.TS.Unix(), Rx: uint64(m.CPU * 100)})
		mem = append(mem, store.Point{TS: m.TS.Unix(), Rx: m.MemUsed, Tx: m.SwapUsed})
		net = append(net, store.Point{TS: m.TS.Unix(), Rx: m.NetRxBps, Tx: m.NetTxBps})
	}
	d.CPU = s.buildChart(cpu, time.Minute, 480, 90, unitPercent, 100)
	d.Mem = s.buildChart(mem, time.Minute, 480, 90, unitBytes, 1)
	d.Net = s.buildChart(net, time.Minute, 480, 90, unitBps, 1)
	if d.Metric.DiskTotal > 0 {
		d.DiskPct = int(float64(d.Metric.DiskUsed) / float64(d.Metric.DiskTotal) * 100)
	}
	if d.Metric.MemTotal > 0 {
		d.MemPct = int(float64(d.Metric.MemUsed) / float64(d.Metric.MemTotal) * 100)
	}
	d.Notify, _ = s.Hub.Store.Notify(ctx)
	d.LoadWarn = d.Notify.LoadHigh > 0 && d.Metric.Load1 > d.Notify.LoadHigh
	d.CPUPct = int(d.Metric.CPU)
	if d.CPUPct > 90 {
		d.CPULvl = "warn"
	}
	d.MemLevel = overLevel(d.MemPct, d.Notify.MemHigh)
	d.DiskLevel = overLevel(d.DiskPct, d.Notify.DiskHigh)
	// Итоги и интерфейсы — только этого сервера (FR-6.3, FR-10.3).
	if ifaces, err := s.Hub.Store.Interfaces(ctx, d.Server.ID); err == nil {
		var all []int64
		for _, i := range ifaces {
			ids, err := s.Hub.Store.InterfacePeerIDs(ctx, i.ID)
			if err == nil {
				all = append(all, ids...)
			}
			card, _ := s.ifaceCard(ctx, i)
			d.Ifaces = append(d.Ifaces, card)
			d.Peers += card.Peers
			d.Online += card.Online
		}
		sortIfaceCards(d.Ifaces)
		d.Totals, _ = s.Hub.Store.PeerTotals(ctx, all)
	}
	// Карточка сервера в парке и его страница обязаны говорить одно и то же, поэтому фраза и
	// уровень считаются тем же кодом.
	card := serverCard{Server: d.Server, Flag: d.Flag, Interfaces: d.Ifaces, Metric: d.Metric,
		Peers: d.Peers, Online: d.Online, Rx24: d.Totals.DayRx, Tx24: d.Totals.DayTx,
		Stale: d.Metric.TS.IsZero() || time.Since(d.Metric.TS) > 10*time.Minute}
	s.fillCard(&card, d.Notify)
	d.Level, d.LevelWord, d.Say = card.Level, card.LevelWord, card.Say
	d.Left, _ = s.Hub.Store.Belongings(ctx, d.Server.ID)
	if d.Server.Retired() {
		d.Level, d.LevelWord = "", "выведен"
		d.Say = "Сервер выведен из парка: панель его не опрашивает, а устройства на нём не подключатся."
	}

	// Размер базы есть только у панели: у удалённого узла своей базы нет.
	if !d.Remote {
		d.DBSize, _ = s.Hub.Store.DBSize(ctx)
	}
	s.render(w, "server.html", d)
}
