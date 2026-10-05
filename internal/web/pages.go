package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/auth"
	"github.com/poznik/awgdash-pub/internal/awg"
	"github.com/poznik/awgdash-pub/internal/clientconf"
	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/node"
	"github.com/poznik/awgdash-pub/internal/qr"
	"github.com/poznik/awgdash-pub/internal/store"
)

// ---------- дашборд ----------

type dashboardData struct {
	Base
	Status     hub.Status
	Servers    []serverCard
	Interfaces []ifaceCard
	Metric     store.HostMetric
	Users      int
	UsersOn    int
	Devices    int
	DevicesOn  int
	Events     []store.Event
	// Экран «Парк» (PLAN-UI §1.2): вердикт словами, очередь дел, кто грузит канал, суточный график парка.
	Verdict verdict
	Tasks   []task
	// Retired — серверы, выведенные из парка: показываются отдельно и молча.
	Retired []serverCard
	Top     []topDevice
	TopRest int
	Chart   Chart
}

// serverCard — сервер парка на обзоре: состояние связи, его интерфейсы и метрики машины
// (SPEC FR-7.4). Панель показывает парк, а не только ту машину, на которой работает.
type serverCard struct {
	store.Server
	Flag       string
	Interfaces []ifaceCard
	Metric     store.HostMetric
	Peers      int
	Online     int
	Devices    int
	Rx24, Tx24 uint64
	// Say — что происходит на сервере, словами; Level — ok | warn | crit для чипа и рамки.
	Say                          string
	Level, LevelWord             string
	DiskPct, MemPct, LoadPct     int
	DiskLevel, MemLevel, LoadLvl string
	// Left — что осталось на выведенном сервере: показывается на его карточке и в подтверждении.
	Left store.ServerBelongings
	// Stale — узел давно не отвечал: связь через туннель рвётся заметно чаще, чем падает сам узел.
	Stale bool
}

type ifaceCard struct {
	store.Interface
	Peers      int
	Online     int
	Unassigned int
	Devices    int
	Rx24, Tx24 uint64
}

// ifaceRank — порядок в списках: сначала то, чем панель управляет, потом наблюдение, в конце
// пропавшие с сервера.
func ifaceRank(mode, status string) int {
	switch {
	case status == store.StatusGone:
		return 2
	case mode != hub.ModeOwn:
		return 1
	default:
		return 0
	}
}

// sortIfaceCards ставит вперёд то, чем панель управляет: наблюдаемые туннели — фон, и в списке
// сервера они не должны заслонять рабочий интерфейс. Пропавшие уходят в конец.
func sortIfaceCards(list []ifaceCard) {
	sort.SliceStable(list, func(i, j int) bool {
		return ifaceRank(list[i].Mode, list[i].Status) < ifaceRank(list[j].Mode, list[j].Status)
	})
}

// ifaceCard считает интерфейс по базе — единственный источник для обзора и страницы сервера.
// Раньше страница сервера брала числа из живого статуса сэмплера, и соседние экраны показывали
// разное количество пиров.
func (s *Server) ifaceCard(ctx context.Context, i store.Interface) (ifaceCard, []store.PeerRow) {
	card := ifaceCard{Interface: i}
	peers, _ := s.Hub.Store.Peers(ctx, i.ID, false)
	now := time.Now()
	for _, p := range peers {
		card.Peers++
		if l, _ := hub.PeerState(p.LastHandshake, now); l == "онлайн" {
			card.Online++
		}
		if !p.DeviceID.Valid {
			card.Unassigned++
		}
		card.Rx24 += p.Rx24
		card.Tx24 += p.Tx24
	}
	card.Devices, _, _ = s.Hub.Store.CountDevices(ctx, i.ID)
	return card, peers
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	d := s.dashboardData(ctx, r, sc, true)
	s.render(w, "dashboard.html", d)
}

// dashboardData собирает обзор. full=false — только то, что показывает живой фрагмент:
// карточки серверов и «кто грузит канал». Считать ради него график парка и очередь дел незачем.
func (s *Server) dashboardData(ctx context.Context, r *http.Request, sc sessionCtx, full bool) dashboardData {
	d := dashboardData{Base: s.base(r, &sc, "Обзор"), Status: s.Hub.Status()}
	d.Section = "dashboard"
	servers, _ := s.Hub.Store.Servers(ctx)
	ifaces, _ := s.Hub.Store.Interfaces(ctx, 0)

	byServer := map[int64][]ifaceCard{}
	peersByIface := map[int64][]store.PeerRow{}
	for _, i := range ifaces {
		card, peers := s.ifaceCard(ctx, i)
		peersByIface[i.ID] = peers
		byServer[i.ServerID] = append(byServer[i.ServerID], card)
		d.Interfaces = append(d.Interfaces, card)
		d.Devices += card.Devices
		d.DevicesOn += card.Online
	}

	for id := range byServer {
		sortIfaceCards(byServer[id])
	}
	for _, srv := range servers {
		card := serverCard{Server: srv, Flag: srv.Flag(), Interfaces: byServer[srv.ID]}
		if srv.Retired() {
			// Выведенный сервер не сломан — его просто больше нет. В вердикт и пороги он не идёт,
			// но показывается карточкой: видно, что на нём осталось, и оттуда же его возвращают
			// или удаляют (FR-10.6, FR-10.7).
			for _, i := range card.Interfaces {
				card.Devices += i.Devices
			}
			card.Left, _ = s.Hub.Store.Belongings(ctx, srv.ID)
			d.Retired = append(d.Retired, card)
			continue
		}
		for _, i := range card.Interfaces {
			card.Peers += i.Peers
			card.Online += i.Online
			card.Devices += i.Devices
			card.Rx24 += i.Rx24
			card.Tx24 += i.Tx24
		}
		if metrics, _ := s.Hub.Store.HostMetrics(ctx, srv.ID, time.Now().Add(-10*time.Minute)); len(metrics) > 0 {
			card.Metric = metrics[len(metrics)-1]
		} else {
			// Метрик за десять минут нет — либо узел молчит, либо туннель до него лёг.
			card.Stale = true
		}
		if srv.Local() {
			d.Metric = card.Metric
		}
		d.Servers = append(d.Servers, card)
	}

	d.Users, d.UsersOn, _ = s.Hub.Store.CountUsers(ctx)
	notify, _ := s.Hub.Store.Notify(ctx)
	for i := range d.Servers {
		s.fillCard(&d.Servers[i], notify)
	}
	d.Top, d.TopRest = s.parkTop(ctx, peersByIface)
	if !full {
		return d
	}
	d.Tasks = s.parkTasks(ctx, &d, notify)
	d.Verdict = parkVerdict(&d)
	d.Chart = s.buildChart(s.parkSeries(ctx, d.Interfaces), time.Hour, 900, 130, unitBytes, 1)
	d.Events, _ = s.Hub.Store.Events(ctx, 6)
	return d
}

// ---------- пользователи ----------

// userRow — строка списка: пользователь и его устройства лейблами (состояние + имя).
type userRow struct {
	store.User
	Devs []deviceChip
}

// deviceChip — устройство в строке списка: имя, состояние точкой, подпись для наведения.
type deviceChip struct {
	Name  string
	Level string
	Title string
}

type usersData struct {
	Base
	// Ifaces — куда можно посадить устройства: в парке из нескольких серверов выбор нужен,
	// на одном сервере он всё равно один и в разметке не показывается.
	Ifaces []ifaceChoice
	// AllIfaces — весь парк, включая наблюдаемые: в настройках доступа человека интерфейс не
	// место посадки, а предмет ограничения, и уже отмеченный наблюдаемый обязан остаться виден.
	AllIfaces []ifaceChoice
	// DefaultHints — подсказки формы создания для интерфейса, отмеченного в ней по умолчанию
	// (первого в списке): без JS форма показывает именно их.
	DefaultHints ifaceHints
	// Orphans — сколько в парке пиров без владельца: они собраны отдельной строкой списка,
	// иначе их приходится искать по одному интерфейсу за раз (FR-1.6).
	Orphans int
	// OrphanPeers — сами эти пиры на своей странице.
	OrphanPeers []store.OrphanPeer
	// Owners — кому можно передать устройства выбранного человека (FR-2.7); считается
	// только на карточке, в списке этот выбор не нужен.
	Owners    []store.UserOption
	Filter    store.UserFilter
	Users     []store.User
	Rows      []userRow
	Total     int
	Page      int
	Pages     int
	Selected  *userDetail
	Link      string
	Range     chartRange
	Ranges    []chartRange
	RangeBase string
}

// ifaceChoice — строка выбора интерфейса: имя сервера рядом с именем интерфейса, иначе
// «awg-hub» ничего не говорит о том, где он живёт.
type ifaceChoice struct {
	ID     int64
	Name   string
	Server string
	Flag   string
	Label  string // флаг и название сервера — то, что видит человек
	Subnet string
	Local  bool
	// Own — панель владеет пирами. Наблюдаемых нет в списке «куда посадить устройство» вовсе
	// (FR-3.1); признак нужен там, где показывается весь парк, — в настройках доступа человека.
	Own bool
	// Hints — что попадёт в конфиг, если «тонкости» оставить пустыми.
	Hints ifaceHints
}

// ifaceHints — значения, которые панель подставит в конфиг сама. Keepalive и AllowedIPs зависят
// от типа устройства (FR-4.3), поэтому у них два варианта: форма показывает тот, что выбран.
type ifaceHints struct {
	DNS, MTU                     string
	Keepalive, KeepaliveRouter   string
	AllowedIPs, AllowedIPsRouter string
}

type userDetail struct {
	store.User
	Devices   []store.Device
	Interface store.Interface
	Endpoints []store.Endpoint
	Audit     []store.AuditEntry
	Totals    store.Totals
	Chart     Chart
	// Say — состояние человека словами; Views — его устройства с выводом по каждому (PLAN-UI §1.4);
	// Groups — те же устройства, разложенные по серверам парка.
	Say    string
	Views  []deviceView
	Groups []deviceGroup
}

// deviceView — устройство так, как его показывает карточка человека.
type deviceView struct {
	store.Device
	Say     string
	Short   string
	Level   string
	Iface   string
	Server  string
	Slug    string
	Flag    string
	Country string
}

// deviceGroup — устройства одного сервера. В парке человек сидит сразу на нескольких, и
// вперемешку карточки читать невозможно: где чьё, видно только по мелкой подписи с адресом.
type deviceGroup struct {
	Server string
	Slug   string
	Flag   string
	// Country — код страны для флага-рисунка (эмодзи в Windows не отображаются).
	Country string
	Retired bool
	Views   []deviceView
}

// groupByServer раскладывает устройства по серверам: живые серверы по названию, выведенные —
// в конец, потому что их устройства уже не работают.
func groupByServer(views []deviceView) []deviceGroup {
	order := map[string]int{}
	var groups []deviceGroup
	for _, v := range views {
		i, ok := order[v.Slug]
		if !ok {
			i = len(groups)
			order[v.Slug] = i
			groups = append(groups, deviceGroup{Server: v.Server, Slug: v.Slug, Flag: v.Flag, Country: v.Country, Retired: v.ServerRetired})
		}
		groups[i].Views = append(groups[i].Views, v)
	}
	sort.SliceStable(groups, func(a, b int) bool {
		if groups[a].Retired != groups[b].Retired {
			return !groups[a].Retired
		}
		return groups[a].Server < groups[b].Server
	})
	return groups
}

const usersPerPage = 60

func (s *Server) users(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	f := userFilterFrom(r)
	page := 1
	if v := atoi64(r.URL.Query().Get("page")); v > 1 {
		page = int(v)
	}

	d := usersData{Base: s.base(r, &sc, "Пользователи"), Filter: f, Page: page}
	d.Section = "users"
	d.Ifaces = s.ifaceChoices(ctx, nil)
	d.DefaultHints = firstHints(d.Ifaces)
	if orphans, err := s.Hub.Store.OrphanPeers(ctx); err == nil {
		d.Orphans = len(orphans)
	}
	var err error
	d.Users, d.Total, err = s.Hub.Store.Users(ctx, f)
	if err != nil {
		s.fail(w, err)
		return
	}
	d.Pages = (d.Total + usersPerPage - 1) / usersPerPage

	d.Rows = s.userRows(ctx, d.Users)
	d.Range, d.Ranges = rangeOf(r.URL.Query().Get("range")), chartRanges
	if id := atoi64(r.PathValue("id")); id > 0 {
		d.RangeBase = "/users/" + itoa(id)
		det, err := s.userDetail(ctx, id, r.URL.Query().Get("range"))
		if err == nil {
			d.Selected = det
			// Настройки доступа живут в карточке: весь парк считается только для неё.
			d.AllIfaces = s.allIfaceChoices(ctx, nil)
			d.Title = det.Name
			if det.Token != "" {
				d.Link = s.portalLink(det.Token)
			}
			if det.DeletedAt.IsZero() {
				d.Owners, _ = s.Hub.Store.UserOptions(ctx)
			}
		}
	}
	s.render(w, "users.html", d)
}

// userRows добирает к списку устройства пользователей — одной выборкой на страницу, а не
// запросом на каждого. В строке они показываются лейблами: видно, что у человека есть и что
// из этого в туннеле.
func (s *Server) userRows(ctx context.Context, users []store.User) []userRow {
	ids := make([]int64, 0, len(users))
	for _, u := range users {
		ids = append(ids, u.ID)
	}
	byUser, err := s.Hub.Store.DevicesOfUsers(ctx, ids)
	if err != nil {
		byUser = map[int64][]store.Device{}
	}
	// Интерфейсы выведенных серверов: устройства на них не работают, и лейбл обязан это сказать.
	retired := map[int64]bool{}
	if servers, err := s.Hub.Store.Servers(ctx); err == nil {
		gone := map[int64]bool{}
		for _, srv := range servers {
			if srv.Retired() {
				gone[srv.ID] = true
			}
		}
		if len(gone) > 0 {
			if ifaces, err := s.Hub.Store.Interfaces(ctx, 0); err == nil {
				for _, i := range ifaces {
					if gone[i.ServerID] {
						retired[i.ID] = true
					}
				}
			}
		}
	}
	rows := make([]userRow, 0, len(users))
	for _, u := range users {
		row := userRow{User: u}
		for _, dev := range byUser[u.ID] {
			chip := deviceChip{Name: dev.Name}
			switch {
			case retired[dev.InterfaceID]:
				chip.Level, chip.Title = "crit", "сервер выведен — не работает"
			case dev.Status != "active":
				chip.Level, chip.Title = "crit", "отключено"
			case dev.Online():
				chip.Level, chip.Title = "ok", "в туннеле, отвечало "+s.fmtAge(dev.LastHandshake)+" назад"
			case dev.LastHandshake.IsZero():
				chip.Title = "ни разу не подключалось"
			default:
				chip.Title = "офлайн " + s.fmtAge(dev.LastHandshake)
			}
			row.Devs = append(row.Devs, chip)
		}
		rows = append(rows, row)
	}
	return rows
}

// userFilterFrom читает фильтры списка из адреса — их же присылает живой фрагмент.
func userFilterFrom(r *http.Request) store.UserFilter {
	q := r.URL.Query()
	f := store.UserFilter{
		Query:       strings.TrimSpace(q.Get("q")),
		Status:      q.Get("status"),
		SelfService: q.Get("self") == "1",
		Online:      q.Get("online") == "1",
		Deleted:     q.Get("trash") == "1",
		Limit:       usersPerPage,
	}
	if v := atoi64(q.Get("page")); v > 1 {
		f.Offset = (int(v) - 1) * usersPerPage
	}
	return f
}

func (s *Server) userDetail(ctx context.Context, id int64, rangeKey string) (*userDetail, error) {
	u, err := s.Hub.Store.UserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	det := &userDetail{User: u}
	det.Devices, err = s.Hub.Store.DevicesByUser(ctx, id)
	if err != nil {
		return nil, err
	}
	ifaceID := u.DefaultInterfaceID
	if ifaceID == 0 && len(det.Devices) > 0 {
		ifaceID = det.Devices[0].InterfaceID
	}
	if ifaceID != 0 {
		if iface, err := s.Hub.Interface(ctx, ifaceID); err == nil {
			det.Interface = iface
			det.Endpoints = clientconf.Endpoints(iface)
		}
	}
	det.Audit, _ = s.Hub.Store.Audit(ctx, store.AuditFilter{TargetType: "user", TargetID: id, Limit: 10})

	ids := make([]int64, 0, len(det.Devices))
	for _, d := range det.Devices {
		ids = append(ids, d.ID)
	}
	growth := map[int64]uint64{}
	lastSeen := map[int64]time.Time{}
	if peers, err := s.Hub.Store.PeerIDsOf(ctx, ids); err == nil {
		det.Totals, _ = s.Hub.Store.PeerTotals(ctx, peers)
		rng := rangeOf(rangeKey)
		bucket := chartBucket(rng, len(peers))
		if points, err := s.Hub.Store.PeerSeries(ctx, peers, s.Hub.ServerID, rng.Since, bucket); err == nil {
			det.Chart = s.buildChart(points, bucket, 480, 110, unitBytes, 1)
		}
		// Прирост счётчиков нужен, чтобы отличить «застряло» от обычного офлайна, а последний
		// трафик — чтобы назвать день, когда устройство замолчало (рукопожатие сбрасывается
		// вместе с интерфейсом).
		g, gErr := s.Hub.Store.PeerGrowth(ctx, peers, 5*time.Minute)
		last, lErr := s.Hub.Store.LastTrafficAt(ctx, peers)
		if gErr == nil || lErr == nil {
			byPeer, _ := s.Hub.Store.DevicesByPeerIDs(ctx, peers)
			for _, d := range byPeer {
				growth[d.ID] = g[d.PeerID]
				if at, ok := last[d.PeerID]; ok {
					lastSeen[d.ID] = at
				}
			}
		}
	}
	det.Say = s.userSay(u)
	det.Views = s.deviceViews(ctx, det.Devices, growth, lastSeen)
	det.Groups = groupByServer(det.Views)
	return det, nil
}

// deviceViews добирает к устройствам вывод словами и то, где они живут.
func (s *Server) deviceViews(ctx context.Context, devices []store.Device, growth map[int64]uint64, lastSeen map[int64]time.Time) []deviceView {
	ifaces := map[int64]store.Interface{}
	out := make([]deviceView, 0, len(devices))
	for _, d := range devices {
		iface, ok := ifaces[d.InterfaceID]
		if !ok {
			iface, _ = s.Hub.Interface(ctx, d.InterfaceID)
			ifaces[d.InterfaceID] = iface
		}
		v := deviceView{Device: d, Iface: iface.Name}
		if srv, err := s.Hub.Store.ServerByID(ctx, iface.ServerID); err == nil {
			v.Server, v.Slug, v.Flag, v.Country = srv.Title, srv.Slug, srv.Flag(), srv.CountryOrGuess()
			v.Device.ServerRetired = srv.Retired()
		}
		v.Say, v.Level = s.deviceSay(v.Device, iface.UnitActive, growth[d.ID], lastSeen[d.ID])
		v.Short, _ = s.deviceShort(v.Device, iface.UnitActive, growth[d.ID], lastSeen[d.ID])
		out = append(out, v)
	}
	return out
}

// portalLink собирает ссылку пользователя. Имя портала берётся из настроек; пока его нет,
// показывается путь — его всё равно можно скопировать и дописать домен.
func (s *Server) portalLink(token string) string {
	if s.PortalHost == "" {
		return "/u/" + token
	}
	return "https://" + s.PortalHost + "/u/" + token
}

// ---------- конфиг устройства ----------

type configData struct {
	Base
	Device    store.Device
	User      store.User
	Interface store.Interface
	Server    store.Server
	Flag      string
	Endpoints []store.Endpoint
	Current   store.Endpoint
	Config    hub.Config
	// Say — состояние устройства словами, Link — ссылка портала: выдать конфиг и отдать ссылку
	// человек хочет одним заходом (PLAN-UI §1.3).
	Say   string
	Level string
	Link  string
	// Hints — что подставит панель, если переопределение оставить пустым.
	Hints ifaceHints
}

func (s *Server) deviceConfig(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	id := atoi64(r.PathValue("id"))
	label := r.URL.Query().Get("ep")
	// Про отказ человек узнаёт на странице устройства, а не голым текстом ошибки: чаще всего
	// это усыновлённый пир, у которого панель не знает приватного ключа (FR-1.6).
	if d, err := s.Hub.Store.DeviceByID(ctx, id); err == nil && !d.HasKey() {
		s.back(w, r, "/devices/"+itoa(id), errors.New("панель не знает приватного ключа этого устройства: "+
			"пир усыновлён или импортирован без него. Выдать конфиг можно, только перевыпустив ключи — "+
			"на клиенте тогда придётся поставить новый"))
		return
	}
	cfg, err := s.Hub.DeviceConfig(ctx, id, label, store.ActorAdmin, s.clientIP(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	iface, err := s.Hub.Interface(ctx, cfg.Device.InterfaceID)
	if err != nil {
		s.fail(w, err)
		return
	}
	u, _ := s.Hub.Store.UserByID(ctx, cfg.Device.UserID)
	d := configData{Base: s.base(r, &sc, cfg.Device.Name), Device: cfg.Device, User: u, Interface: iface,
		Endpoints: clientconf.Endpoints(iface), Current: cfg.Endpoint, Config: cfg, Hints: hintsOfIface(iface)}
	d.Section = "users"
	if srv, err := s.Hub.Store.ServerByID(ctx, iface.ServerID); err == nil {
		d.Server, d.Flag = srv, srv.Flag()
	}
	var growth uint64
	var lastSeen time.Time
	if peers, err := s.Hub.Store.PeerIDsOf(ctx, []int64{cfg.Device.ID}); err == nil {
		if g, err := s.Hub.Store.PeerGrowth(ctx, peers, 5*time.Minute); err == nil {
			for _, v := range g {
				growth += v
			}
		}
		if last, err := s.Hub.Store.LastTrafficAt(ctx, peers); err == nil {
			for _, at := range last {
				if at.After(lastSeen) {
					lastSeen = at
				}
			}
		}
	}
	d.Device.ServerRetired = d.Server.Retired()
	d.Say, d.Level = s.deviceSay(d.Device, iface.UnitActive, growth, lastSeen)
	if u.Token != "" {
		d.Link = s.portalLink(u.Token)
	}
	s.render(w, "config.html", d)
}

// deviceConfFile отдаёт .conf файлом (FR-4.5).
func (s *Server) deviceConfFile(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	cfg, err := s.Hub.DeviceConfig(ctx, atoi64(r.PathValue("id")), r.URL.Query().Get("ep"), store.ActorAdmin, s.clientIP(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+urlPathEscape(cfg.FileName))
	w.Header().Set("Cache-Control", "no-store")
	w.Write([]byte(cfg.Text))
}

// ---------- интерфейсы ----------

type interfacesData struct {
	Base
	Interfaces []store.Interface
	Selected   *interfaceDetail
	Users      []store.User // для привязки ничьих пиров к людям
	Range      chartRange
	Ranges     []chartRange
	RangeBase  string
	// Gone — что уйдёт, если убрать из панели интерфейс, пропавший с сервера (FR-1.9).
	Gone store.ServerBelongings
	// Plan — предпросмотр сверки: что панель поставит, обновит и снимет, если нажать
	// «Привести к панели». Считается по запросу (?plan=1) и ничего не меняет (PLAN-UI §1.5).
	Plan     *node.ReconcileResult
	PlanErr  string
	PlanKeys map[string]string // ключ пира → человеческое имя, чтобы список читался
	// Сервер интерфейса: интерфейс живёт внутри машины, туда же ведёт кнопка «назад».
	ServerSlug  string
	ServerTitle string
	IfaceSay    string
}

// peersPerPage — сколько пиров показывается за раз. На парке из 600 устройств полный список
// весит 280 КБ при бюджете страницы 60 (§7.1), поэтому таблица листается.
const peersPerPage = 60

type interfaceDetail struct {
	store.Interface
	Obf   []awg.KV
	Peers []peerRow
	// PeerPage — какая страница таблицы показана; PeerPages — сколько их всего.
	PeerPage   int
	PeerPages  int
	PeerTotal  int
	Online     int
	Unassigned int
	Readiness  hub.ModeReadiness
	Endpoints  []store.Endpoint
	Rx24, Tx24 uint64
	Now        interfaceNow
	Totals     store.Totals
	Chart      Chart
}

type peerRow struct {
	store.PeerRow
	Device string
	User   string
	State  string
	Class  string
}

func (s *Server) interfaces(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	d := interfacesData{Base: s.base(r, &sc, "Интерфейсы")}
	d.Section = "interfaces"
	var err error
	d.Interfaces, err = s.Hub.Store.Interfaces(ctx, 0)
	if err != nil {
		s.fail(w, err)
		return
	}
	// Внутри сервера — сначала управляемые: наблюдаемые туннели есть на каждой машине, и в
	// общем списке они заслоняли рабочие интерфейсы.
	sort.SliceStable(d.Interfaces, func(i, j int) bool {
		a, b := d.Interfaces[i], d.Interfaces[j]
		if a.ServerID != b.ServerID {
			return a.ServerID < b.ServerID
		}
		return ifaceRank(a.Mode, a.Status) < ifaceRank(b.Mode, b.Status)
	})
	// Без имени в адресе показывается список интерфейсов, с именем — сам интерфейс.
	ref := r.PathValue("name")
	d.Range, d.Ranges = rangeOf(r.URL.Query().Get("range")), chartRanges
	d.RangeBase = "/interfaces/" + ref
	if det, err := s.interfaceDetail(ctx, ref); err == nil {
		d.Selected = det
		d.Title = det.Name
		s.fillNow(ctx, det)
		if peers, err := s.Hub.Store.InterfacePeerIDs(ctx, det.ID); err == nil {
			det.Totals, _ = s.Hub.Store.PeerTotals(ctx, peers)
			bucket := chartBucket(d.Range, len(peers))
			if points, err := s.Hub.Store.PeerSeries(ctx, peers, s.Hub.ServerID, d.Range.Since, bucket); err == nil {
				det.Chart = s.buildChart(points, bucket, 480, 120, unitBytes, 1)
			}
		}
		if srv, err := s.Hub.Store.ServerByID(ctx, det.ServerID); err == nil {
			d.ServerSlug, d.ServerTitle = srv.Slug, srv.Flag()+" "+srv.Title
		}
		d.IfaceSay = s.ifaceSay(det)
		if det.Status == store.StatusGone {
			d.Gone, _ = s.Hub.Store.InterfaceBelongings(ctx, det.ID)
		}
		pagePeers(det, atoi64(r.URL.Query().Get("peers")))
		if det.Unassigned > 0 {
			d.Users, _, _ = s.Hub.Store.Users(ctx, store.UserFilter{Limit: 200})
		}
		// Предпросмотр сверки: смотреть, что изменится, нужно до нажатия, а не после.
		if r.URL.Query().Get("plan") == "1" {
			plan, err := s.Hub.PlanReconcile(ctx, det.ID)
			if err != nil {
				d.PlanErr = err.Error()
			} else {
				d.Plan = &plan
				d.PlanKeys = map[string]string{}
				for _, p := range det.Peers {
					name := p.Device
					if name == "" {
						name = "пир без владельца"
					} else if p.User != "" {
						name += " · " + p.User
					}
					d.PlanKeys[p.PublicKey] = name
				}
			}
		}
	}
	s.render(w, "interfaces.html", d)
}

// interfaceDetail собирает карточку интерфейса: пиры с их устройствами, обфускация, готовность
// к own. Нужен и странице, и живому фрагменту. Ссылка — идентификатор из адреса (имя тоже
// принимается, см. interfaceRef).
func (s *Server) interfaceDetail(ctx context.Context, ref string) (*interfaceDetail, error) {
	list, err := s.Hub.Store.Interfaces(ctx, 0)
	if err != nil {
		return nil, err
	}
	wantID := atoi64(ref)
	now := time.Now()
	for _, i := range list {
		if wantID > 0 && i.ID != wantID {
			continue
		}
		if wantID == 0 && i.Name != ref {
			continue
		}
		det := &interfaceDetail{Interface: i, Endpoints: clientconf.Endpoints(i)}
		for _, k := range awg.ObfKeys {
			if v := i.Obfuscation[k]; v != "" {
				det.Obf = append(det.Obf, awg.KV{Key: k, Value: v})
			}
		}
		peers, _ := s.Hub.Store.Peers(ctx, i.ID, false)
		peerIDs := make([]int64, 0, len(peers))
		for _, p := range peers {
			peerIDs = append(peerIDs, p.ID)
		}
		// Рост счётчиков за пять минут отличает «офлайн» от «застрял» (FR-6.2).
		growth, _ := s.Hub.Store.PeerGrowth(ctx, peerIDs, 5*time.Minute)
		linked := make([]int64, 0, len(peers))
		for _, p := range peers {
			if p.DeviceID.Valid {
				linked = append(linked, p.DeviceID.Int64)
			}
		}
		devices, _ := s.Hub.Store.DevicesByIDs(ctx, linked)
		byID := map[int64]store.Device{}
		for _, dev := range devices {
			byID[dev.ID] = dev
		}
		for _, p := range peers {
			row := peerRow{PeerRow: p}
			if p.DeviceID.Valid {
				if dev, ok := byID[p.DeviceID.Int64]; ok {
					row.Device, row.User = dev.Name, dev.UserName
				}
			} else {
				det.Unassigned++
			}
			row.State, row.Class = hub.PeerStateFull(p.LastHandshake, growth[p.ID], now)
			if row.State == "онлайн" {
				det.Online++
			}
			det.Rx24 += p.Rx24
			det.Tx24 += p.Tx24
			det.Peers = append(det.Peers, row)
		}
		sort.Slice(det.Peers, func(a, b int) bool { return det.Peers[a].LastHandshake.After(det.Peers[b].LastHandshake) })
		det.PeerTotal = len(det.Peers)
		if rd, err := s.Hub.ModeReadiness(ctx, i.ID, false); err == nil {
			det.Readiness = rd
		}
		return det, nil
	}
	return nil, errors.New("интерфейс " + ref + " не найден")
}

// ---------- события и аудит ----------

type eventsData struct {
	Base
	Events []store.Event
	Audit  []store.AuditEntry
	Tab    string
	Page   int
	Pages  int
	Total  int
}

// eventsPerPage — журнал листается: 200 записей разом не влезают в бюджет страницы (ТЗ §7.1).
const eventsPerPage = 60

func (s *Server) events(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	d := eventsData{Base: s.base(r, &sc, "Журнал"), Tab: r.URL.Query().Get("tab")}
	d.Section = "events"
	if d.Tab != "audit" {
		d.Tab = "events"
	}
	d.Page = 1
	if v := atoi64(r.URL.Query().Get("page")); v > 1 {
		d.Page = int(v)
	}
	offset := (d.Page - 1) * eventsPerPage
	if d.Tab == "audit" {
		d.Audit, _ = s.Hub.Store.Audit(ctx, store.AuditFilter{Limit: eventsPerPage, Offset: offset})
		d.Total, _ = s.Hub.Store.CountAudit(ctx)
	} else {
		d.Events, _ = s.Hub.Store.Events(ctx, eventsPerPage, offset)
		d.Total, _ = s.Hub.Store.CountEvents(ctx)
	}
	d.Pages = (d.Total + eventsPerPage - 1) / eventsPerPage
	s.render(w, "events.html", d)
}

// ---------- настройки ----------

type settingsData struct {
	Base
	Me       adminView
	Sessions []store.Session
	Current  string
	Config   settingsConfig
	TOTPQR   string // QR секрета второго фактора, пока он не подтверждён
	TOTPKey  string // тот же секрет строкой — если камера не сработала
	Passkeys []store.Passkey
	Backups  []hub.BackupFile
	Backup   backupView
	Notify   store.NotifyConfig
	BotOn    bool         // токен задан — оповещатель работает
	Kinds    []notifyKind // виды событий, которые разрешено выключить
}

// backupView — состояние резервного копирования для страницы настроек (SPEC §6.9).
type backupView struct {
	Enabled    bool   // задан публичный ключ age
	Recipient  string // ключ показывается частично: целиком он не секрет, но и не нужен
	Dir        string
	SCPTarget  string
	LastAt     time.Time
	ToTelegram bool
}

// notifyKind — строка списка «о чём сообщать»: молчать имеет смысл о шумном и рутинном,
// а о падении интерфейса выключателя нет намеренно.
type notifyKind struct {
	Kind  string
	Title string
	Off   bool
}

// notifyKinds — что администратор вправе выключить (SPEC FR-8.2).
var notifyKinds = []struct{ kind, title string }{
	{"device_first_online", "первое подключение устройства"},
	{"self_service_device", "устройство создано по ссылке"},
	{"self_service_rename", "устройство переименовано по ссылке"},
	{"self_service_delete", "устройство удалено по ссылке"},
	{"device_created", "устройство создано в панели"},
	{"device_deleted", "устройство удалено"},
	{"user_created", "пользователь создан"},
	{"user_deleted", "пользователь удалён"},
	{"traffic_spike", "всплеск трафика"},
	{"counters_reset", "сброс счётчиков"},
	{"panel_started", "панель запущена"},
	{"purge", "корзина очищена"},
}

// adminView — то, что о администраторе можно показать. Хеш пароля и секрет TOTP сюда не попадают:
// страница один раз уже напечатала целиком структуру store.Admin в атрибуте title.
type adminView struct {
	Username    string
	LastLoginAt time.Time
	TOTPEnabled bool
	TOTPPending bool
}

type settingsConfig struct {
	AdminHost  string
	PortalHost string
	TZ         string
	DataDir    string
	DBPath     string
	Sample     time.Duration
	Foreign    []string
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	d := settingsData{Base: s.base(r, &sc, "Настройки"), Current: sc.Session.ID,
		Me: adminView{Username: sc.Admin.Username, LastLoginAt: sc.Admin.LastLoginAt,
			TOTPEnabled: sc.Admin.TOTPEnabled, TOTPPending: sc.Admin.TOTPSecret != "" && !sc.Admin.TOTPEnabled}}
	d.Section = "settings"
	d.Sessions, _ = s.Hub.Store.Sessions(ctx, sc.Admin.ID)
	// Секрет показывается только пока второй фактор не включён: дальше он не нужен и не показывается.
	if sc.Admin.TOTPSecret != "" && !sc.Admin.TOTPEnabled {
		if svg, err := qr.SVG(auth.TOTPURI("awgdash", sc.Admin.Username, sc.Admin.TOTPSecret)); err == nil {
			d.TOTPQR, d.TOTPKey = svg, sc.Admin.TOTPSecret
		}
	}
	if c := s.Hub.Cfg; c != nil {
		d.Config = settingsConfig{AdminHost: c.AdminHost, PortalHost: c.PortalHost, TZ: c.TZ,
			DataDir: c.DataDir, DBPath: c.DBPath, Sample: c.SampleEvery, Foreign: c.ForeignManagers}
		d.BotOn = c.TelegramToken != ""
	}
	d.Passkeys, _ = s.Hub.Store.Passkeys(ctx, sc.Admin.ID)
	d.Backups, _ = s.Hub.Backups()
	d.Backup = backupView{Dir: s.Hub.BackupDir(), ToTelegram: s.Hub.Bot != nil}
	if c := s.Hub.Cfg; c != nil {
		d.Backup.Enabled = strings.TrimSpace(c.AgeRecipient) != ""
		d.Backup.Recipient = shortKey(c.AgeRecipient)
		d.Backup.SCPTarget = c.BackupSCPTarget
	}
	if len(d.Backups) > 0 {
		d.Backup.LastAt = d.Backups[0].At
	}
	d.JS = append(d.JS, s.asset("passkey.js"))
	d.Notify, _ = s.Hub.Store.Notify(ctx)
	for _, k := range notifyKinds {
		d.Kinds = append(d.Kinds, notifyKind{Kind: k.kind, Title: k.title, Off: d.Notify.IsOff(k.kind)})
	}
	s.render(w, "settings.html", d)
}

// sparkline раскладывает ряд по холсту w×h и возвращает точки для <polyline>.
// Пустой ряд даёт пустую строку — шаблон тогда не рисует график вовсе.
func sparkline(values []uint64, w, h int) (string, uint64) {
	if len(values) == 0 {
		return "", 0
	}
	var max uint64
	for _, v := range values {
		if v > max {
			max = v
		}
	}
	if max == 0 {
		return "", 0
	}
	var b strings.Builder
	step := float64(w) / float64(maxInt(len(values)-1, 1))
	for i, v := range values {
		x := float64(i) * step
		y := float64(h) - float64(v)/float64(max)*float64(h)
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", x, y)
	}
	return b.String(), max
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// urlPathEscape кодирует имя файла для Content-Disposition (в нём кириллица).
func urlPathEscape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strings.IndexByte("-_.~", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteByte('%')
		b.WriteByte(hex[c>>4])
		b.WriteByte(hex[c&15])
	}
	return b.String()
}

// ---------- живые фрагменты ----------

// liveDashboard отдаёт живую часть обзора: карточки серверов и тех, кто грузит канал.
func (s *Server) liveDashboard(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	s.Hub.SampleAllNow(ctx)
	d := s.dashboardData(ctx, r, sc, false)
	s.renderPartial(w, "live-dashboard", d)
}

// liveUsers отдаёт список пользователей с их состоянием.
func (s *Server) liveUsers(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	d := usersData{Base: s.base(r, &sc, "Пользователи")}
	f := userFilterFrom(r)
	var err error
	d.Filter = f
	d.Users, d.Total, err = s.Hub.Store.Users(ctx, f)
	if err != nil {
		s.fail(w, err)
		return
	}
	d.Rows = s.userRows(ctx, d.Users)
	if id := atoi64(r.URL.Query().Get("id")); id > 0 {
		if u, err := s.Hub.Store.UserByID(ctx, id); err == nil {
			d.Selected = &userDetail{User: u}
		}
	}
	s.renderPartial(w, "live-users", d)
}

// liveUser отдаёт счётчики карточки пользователя (таблицу устройств не трогаем: там формы).
func (s *Server) liveUser(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	det, err := s.userDetail(ctx, atoi64(r.PathValue("id")), r.URL.Query().Get("range"))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.renderPartial(w, "live-user", det)
}

// liveInterface отдаёт таблицу пиров интерфейса.
func (s *Server) liveInterface(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	d := interfacesData{Base: s.base(r, &sc, "Интерфейсы")}
	det, err := s.interfaceDetail(ctx, r.PathValue("name"))
	if err != nil {
		s.fail(w, err)
		return
	}
	// Внеочередная выборка идёт по идентификатору: имя в парке не уникально.
	s.Hub.SampleNow(ctx, det.ID)
	if fresh, err := s.interfaceDetail(ctx, itoa(det.ID)); err == nil {
		det = fresh
	}
	pagePeers(det, atoi64(r.URL.Query().Get("peers")))
	d.Selected = det
	if det.Unassigned > 0 {
		d.Users, _, _ = s.Hub.Store.Users(ctx, store.UserFilter{Limit: 200})
	}
	s.renderPartial(w, "live-interface", d)
}

// pagePeers режет таблицу пиров на страницы. Онлайн, «кто грузит» и сверка считаются раньше и
// по всем пирам — листается только показ.
func pagePeers(det *interfaceDetail, page int64) {
	det.PeerPage = 1
	if page > 1 {
		det.PeerPage = int(page)
	}
	det.PeerPages = (det.PeerTotal + peersPerPage - 1) / peersPerPage
	if det.PeerPages > 0 && det.PeerPage > det.PeerPages {
		det.PeerPage = det.PeerPages
	}
	from := (det.PeerPage - 1) * peersPerPage
	if from > len(det.Peers) {
		from = len(det.Peers)
	}
	to := from + peersPerPage
	if to > len(det.Peers) {
		to = len(det.Peers)
	}
	det.Peers = det.Peers[from:to]
}

// orphans — все пиры парка, за которыми в панели никого нет. Это не пользователь: строка в
// списке ведёт сюда, чтобы разобрать их одним заходом, а не искать внутри каждого интерфейса.
func (s *Server) orphans(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	d := usersData{Base: s.base(r, &sc, "Пиры-сироты")}
	d.Section = "users"
	list, err := s.Hub.Store.OrphanPeers(ctx)
	if err != nil {
		s.fail(w, err)
		return
	}
	d.OrphanPeers, d.Orphans = list, len(list)
	if len(list) > 0 {
		d.Users, _, _ = s.Hub.Store.Users(ctx, store.UserFilter{Limit: 500})
	}
	s.render(w, "orphans.html", d)
}

// ifaceChoices собирает список интерфейсов, куда можно посадить устройство: имя сервера
// подставляется из реестра, чтобы «awg-hub» не выглядел как ещё один интерфейс той же машины.
// Наблюдаемых здесь нет — их отсеивает хаб (FR-3.1).
func (s *Server) ifaceChoices(ctx context.Context, u *store.User) []ifaceChoice {
	list, err := s.Hub.IfaceChoices(ctx, u)
	if err != nil {
		return nil
	}
	return ifaceChoicesOf(list)
}

// allIfaceChoices — весь парк, включая наблюдаемые: нужен настройкам доступа человека.
func (s *Server) allIfaceChoices(ctx context.Context, u *store.User) []ifaceChoice {
	list, err := s.Hub.AllIfaceChoices(ctx, u)
	if err != nil {
		return nil
	}
	return ifaceChoicesOf(list)
}

func ifaceChoicesOf(list []hub.IfaceChoice) []ifaceChoice {
	out := make([]ifaceChoice, 0, len(list))
	for _, c := range list {
		out = append(out, ifaceChoice{ID: c.InterfaceID, Name: c.Interface, Server: c.Server,
			Flag: c.Flag, Label: c.Label(), Subnet: c.Subnet, Local: c.Local, Own: c.Own, Hints: hintsOf(c)})
	}
	return out
}

// deviceNew — отдельная страница создания устройства: та же форма, что в модалке.
// Нужна как запасной путь: без JS диалог не открывается, а завести устройство надо.
func (s *Server) deviceNew(w http.ResponseWriter, r *http.Request, sc sessionCtx) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	id := atoi64(r.PathValue("id"))
	u, err := s.Hub.Store.UserByID(ctx, id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	d := usersData{Base: s.base(r, &sc, "Новое устройство"), Ifaces: s.ifaceChoices(ctx, &u)}
	d.DefaultHints = firstHints(d.Ifaces)
	d.Section = "users"
	detail := &userDetail{User: u}
	detail.Devices, _ = s.Hub.Store.DevicesByUser(ctx, u.ID)
	d.Selected = detail
	s.render(w, "device-new.html", d)
}
