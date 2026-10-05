package web

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/store"
	"github.com/poznik/awgdash-pub/internal/version"
)

// Экран «Парк»: вердикт словами, карточка на сервер, очередь «Надо сделать» (design.md, PLAN-UI §1.2).
// Панель делает вывод сама — цифры под фразой служат подтверждением, а не заменой.

// task — дело в очереди. Level: "" обычное, "warn", "crit".
type task struct {
	Level  string
	What   string
	Why    string
	Href   string
	Action string
	// Verdict — как это дело звучит во второй строке вердикта; пусто — в вердикт не выносится.
	Verdict string
}

// verdict — две строки над обзором и объяснение под ними.
type verdict struct {
	Head string
	Bad  string
	Crit bool
	Why  string
}

// parkVerdict собирает вердикт из тех же фактов, что и очередь задач: расходиться им нельзя.
func parkVerdict(d *dashboardData) verdict {
	v := verdict{Head: "Всё работает."}
	alive := 0
	for _, s := range d.Servers {
		if !s.Stale {
			alive++
		}
	}
	switch {
	case len(d.Servers) == 0:
		v.Head, v.Why = "Серверов пока нет.", "Добавьте узел командой awgdash server add."
		return v
	case alive == 0:
		v.Head, v.Crit = "Панель не видит ни одного сервера.", true
	case alive < len(d.Servers):
		v.Head, v.Crit = "Часть парка молчит.", true
	}
	for _, t := range d.Tasks {
		if t.Verdict == "" {
			continue
		}
		if t.Level == "crit" {
			v.Bad, v.Crit = t.Verdict, true
			break
		}
		if v.Bad == "" && t.Level == "warn" {
			v.Bad = t.Verdict
		}
	}
	v.Why = fmt.Sprintf("%s в туннеле, %s из %s отвечают.",
		plural(d.DevicesOn, "устройство", "устройства", "устройств"),
		plural(alive, "сервер", "сервера", "серверов"),
		plural(len(d.Servers), "", "", ""))
	if n := len(d.Tasks); n > 0 {
		v.Why += " " + plural(n, "активная задача ожидает", "активные задачи ожидают", "активных задач ожидают") + "."
	}
	return v
}

// parkTasks — очередь дел. Источники перечислены в PLAN-UI §1.2: всё, что панель заметила,
// но сделать сама не может.
func (s *Server) parkTasks(ctx context.Context, d *dashboardData, cfg store.NotifyConfig) []task {
	var out []task
	for _, srv := range d.Servers {
		if srv.Stale {
			out = append(out, task{Level: "crit", What: srv.Title + ": узел не отвечает",
				Why:  "последняя связь " + s.fmtAge(srv.LastSeenAt) + " назад; проверьте туннель и сам сервер",
				Href: "/servers/" + srv.Slug, Action: "Открыть сервер",
				Verdict: srv.Title + " не отвечает."})
			continue
		}
		// Узлы обновляются по одной машине, и на отставшем то же действие ведёт себя иначе:
		// сверка обфускации на узле от 24.08 считала «пусто» и «0» разными и красила исправный
		// интерфейс. Видно это должно быть в панели, а не при чтении журналов (FR-10.5).
		if !srv.Local() && srv.AwgdashVersion != "" && srv.AwgdashVersion != version.Version {
			out = append(out, task{Level: "warn", What: srv.Title + ": узел отстал от панели",
				Why:  "на узле " + srv.AwgdashVersion + ", на хабе " + version.Version + " — проверки на узле идут по его версии; обновите: make deploy HOST=" + srv.Slug,
				Href: "/servers/" + srv.Slug, Action: "Открыть сервер"})
		}
		if srv.RebootRequired {
			out = append(out, task{Level: "warn", What: srv.Title + ": нужна перезагрузка",
				Why:  "ядро обновилось — панель туннели не трогает, перезагрузка делается руками",
				Href: "/servers/" + srv.Slug, Action: "Открыть сервер",
				Verdict: srv.Title + " просит перезагрузку."})
		}
		if p := pctOf(srv.Metric.DiskUsed, srv.Metric.DiskTotal); p >= cfg.DiskHigh {
			out = append(out, task{Level: "crit", What: fmt.Sprintf("%s: диск занят на %d %%", srv.Title, p),
				Why:  fmt.Sprintf("порог тревоги %d %%; чистить нечего — база панели растёт медленно, смотрите журналы", cfg.DiskHigh),
				Href: "/servers/" + srv.Slug, Action: "Открыть сервер",
				Verdict: fmt.Sprintf("%s: диск занят на %d %%.", srv.Title, p)})
		}
		if p := pctOf(srv.Metric.MemUsed, srv.Metric.MemTotal); p >= cfg.MemHigh {
			out = append(out, task{Level: "warn", What: fmt.Sprintf("%s: память занята на %d %%", srv.Title, p),
				Why: fmt.Sprintf("порог тревоги %d %%", cfg.MemHigh), Href: "/servers/" + srv.Slug, Action: "Открыть сервер",
				Verdict: fmt.Sprintf("%s: память занята на %d %%.", srv.Title, p)})
		}
		if cfg.LoadHigh > 0 && srv.Metric.Load1 > cfg.LoadHigh {
			out = append(out, task{Level: "warn", What: fmt.Sprintf("%s: нагрузка %.2f", srv.Title, srv.Metric.Load1),
				Why: fmt.Sprintf("порог тревоги %.1f", cfg.LoadHigh), Href: "/servers/" + srv.Slug, Action: "Открыть сервер"})
		}
	}
	for _, i := range d.Interfaces {
		// Интерфейса нет на сервере: это не поломка туннеля, а забытая запись — на ней висят
		// устройства и история, поэтому панель предлагает убрать её руками (FR-1.9).
		if i.Status == store.StatusGone {
			out = append(out, task{Level: "warn", What: i.Name + ": исчез с сервера",
				Why:  "конфига на машине больше нет — панель держит его записи, пока их не убрать",
				Href: "/interfaces/" + itoa(i.ID), Action: "Убрать из панели"})
			continue
		}
		if !i.UnitActive {
			out = append(out, task{Level: "crit", What: i.Name + ": интерфейс не поднят",
				Why:  "туннель не работает ни у кого; поднимается systemd — awg-quick@" + i.Name,
				Href: "/interfaces/" + itoa(i.ID), Action: "Открыть интерфейс",
				Verdict: i.Name + " не поднят."})
			continue
		}
		if i.LastVerifyOK != nil && !*i.LastVerifyOK {
			out = append(out, task{Level: "crit", What: i.Name + ": обфускация расходится",
				Why:  "параметры в файле и в рантайме не совпадают — клиенты могут не подключиться",
				Href: "/interfaces/" + itoa(i.ID), Action: "Открыть интерфейс",
				Verdict: i.Name + ": обфускация расходится."})
		}
		if i.Unassigned > 0 {
			out = append(out, task{Level: "warn",
				What: fmt.Sprintf("%s: %s без владельца", i.Name, plural(i.Unassigned, "пир", "пира", "пиров")),
				Why:  "приватных ключей панель не знает — конфиг таким не выдать, только привязать к пользователю",
				Href: "/interfaces/" + itoa(i.ID), Action: "Разобрать",
				Verdict: fmt.Sprintf("на %s %s без владельца.", i.Name, plural(i.Unassigned, "пир", "пира", "пиров"))})
		}

	}
	for _, srv := range d.Retired {
		b, err := s.Hub.Store.Belongings(ctx, srv.ID)
		if err != nil || b.Devices == 0 {
			continue
		}
		out = append(out, task{Level: "warn",
			What: fmt.Sprintf("%s выведен, но на нём осталось %s", srv.Title, plural(b.Devices, "устройство", "устройства", "устройств")),
			Why: fmt.Sprintf("у %s: эти конфиги уже не работают — раздайте людям новые на живом сервере, потом сервер можно удалить из панели",
				plural(b.Users, "пользователя", "пользователей", "пользователей")),
			Href: "/servers/" + srv.Slug, Action: "Открыть сервер",
			Verdict: ""})
	}
	if expired, err := s.Hub.Store.ExpiredUsers(ctx); err == nil && len(expired) > 0 {
		names := expired[0].Name
		if len(expired) > 1 {
			names = fmt.Sprintf("%s и ещё %d", names, len(expired)-1)
		}
		t := task{Level: "warn", What: "Истёк срок доступа: " + names,
			Why: "устройства сняты с интерфейса; продлите срок в карточке или удалите пользователя", Action: "Открыть"}
		if len(expired) == 1 {
			t.Href = fmt.Sprintf("/users/%d", expired[0].ID)
		} else {
			t.Href = "/users"
		}
		out = append(out, t)
	}
	if files, err := s.Hub.Backups(); err == nil {
		switch {
		case len(files) == 0:
			out = append(out, task{Level: "warn", What: "Резервных копий нет",
				Why:  "без ключа age панель копии не делает — ключ заводится командой awgdash backup keygen --install",
				Href: "/settings", Action: "Настройки"})
		case time.Since(files[0].At) > 48*time.Hour:
			out = append(out, task{Level: "warn", What: "Копия не делалась " + s.fmtAge(files[0].At),
				Why: "расписание — ежедневно в 03:30; проверьте журнал панели", Href: "/settings", Action: "Настройки"})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i].Level) < rank(out[j].Level) })
	return out
}

func rank(level string) int {
	switch level {
	case "crit":
		return 0
	case "warn":
		return 1
	}
	return 2
}

func pctOf(used, total uint64) int {
	if total == 0 {
		return 0
	}
	return int(float64(used) / float64(total) * 100)
}

// say — фраза о сервере: что происходит прямо сейчас, человеческими словами.
func (s *Server) say(c serverCard) string {
	if c.Stale {
		return "Узел не отвечает — последняя связь " + s.fmtAge(c.LastSeenAt) + " назад. Данные ниже с того момента."
	}
	// «Прошло» — весь объём через сервер: скачанное клиентами плюс отданное ими.
	head := fmt.Sprintf("%s онлайн из %d, за сутки прошло %s.",
		plural(c.Online, "устройство", "устройства", "устройств"), c.Peers, fmtBytes(c.Rx24+c.Tx24))
	if c.Peers == 0 {
		head = "Пиров на интерфейсах пока нет."
	}
	var bad []string
	if p := pctOf(c.Metric.DiskUsed, c.Metric.DiskTotal); p >= 85 {
		bad = append(bad, fmt.Sprintf("диск занят на %d %%", p))
	}
	if p := pctOf(c.Metric.MemUsed, c.Metric.MemTotal); p >= 90 {
		bad = append(bad, fmt.Sprintf("память занята на %d %%", p))
	}
	if c.Metric.Load1 > 2 {
		bad = append(bad, fmt.Sprintf("нагрузка %.2f", c.Metric.Load1))
	}
	if c.RebootRequired {
		bad = append(bad, "ядро ждёт перезагрузки")
	}
	if len(bad) == 0 {
		return head + " Место, память и нагрузка в норме."
	}
	return head + " Но " + joinRu(bad) + "."
}

func joinRu(parts []string) string {
	switch len(parts) {
	case 0:
		return ""
	case 1:
		return parts[0]
	}
	out := ""
	for i, p := range parts {
		switch {
		case i == 0:
			out = p
		case i == len(parts)-1:
			out += " и " + p
		default:
			out += ", " + p
		}
	}
	return out
}

// parkTop — кто грузит канал сейчас, по всему парку. Возвращает тройку и сколько осталось за ней.
// Пиры приходят уже загруженными: обзор и так их читал, второй проход по 600 строкам был лишним.
func (s *Server) parkTop(ctx context.Context, byIface map[int64][]store.PeerRow) ([]topDevice, int) {
	var out []topDevice
	for _, peers := range byIface {
		ids := make([]int64, 0, len(peers))
		byDevice := map[int64]int64{}
		for _, p := range peers {
			ids = append(ids, p.ID)
			if p.DeviceID.Valid {
				byDevice[p.ID] = p.DeviceID.Int64
			}
		}
		speeds, err := s.Hub.Store.PeerSpeeds(ctx, ids, time.Minute)
		if err != nil {
			continue
		}
		// Имена добираются только для тех, кто реально что-то качает: обычно это единицы.
		var loud []int64
		for _, p := range peers {
			if sp, ok := speeds[p.ID]; ok && (sp.RxBps > 0 || sp.TxBps > 0) {
				if id, ok := byDevice[p.ID]; ok {
					loud = append(loud, id)
				}
			}
		}
		names := map[int64]store.Device{}
		if devs, err := s.Hub.Store.DevicesByIDs(ctx, loud); err == nil {
			for _, d := range devs {
				names[d.ID] = d
			}
		}
		for _, p := range peers {
			sp, ok := speeds[p.ID]
			if !ok || (sp.RxBps == 0 && sp.TxBps == 0) {
				continue
			}
			row := topDevice{Name: shortKey(p.PublicKey), RxBps: sp.RxBps, TxBps: sp.TxBps}
			if dev, ok := names[byDevice[p.ID]]; ok {
				row.Name, row.User = dev.Name, dev.UserName
			}
			state, _ := hub.PeerState(p.LastHandshake, time.Now())
			row.Online = state == "онлайн"
			out = append(out, row)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RxBps+out[i].TxBps > out[j].RxBps+out[j].TxBps })
	rest := 0
	if len(out) > 3 {
		rest = len(out) - 3
		out = out[:3]
	}
	return out, rest
}

// parkSeries — суточный трафик всего парка одной линией.
func (s *Server) parkSeries(ctx context.Context, ifaces []ifaceCard) []store.Point {
	merged := map[int64]*store.Point{}
	var order []int64
	for _, i := range ifaces {
		ts, rx, tx, err := s.Hub.Store.TrafficSeries(ctx, i.ID, time.Now().Add(-24*time.Hour), time.Hour)
		if err != nil {
			continue
		}
		for k, at := range ts {
			p, ok := merged[at]
			if !ok {
				p = &store.Point{TS: at}
				merged[at] = p
				order = append(order, at)
			}
			p.Rx += rx[k]
			p.Tx += tx[k]
		}
	}
	sort.Slice(order, func(a, b int) bool { return order[a] < order[b] })
	out := make([]store.Point, 0, len(order))
	for _, at := range order {
		out = append(out, *merged[at])
	}
	return out
}

// serverLevel — состояние карточки сервера: чип, рамка и значок берут его отсюда.
func serverLevel(c serverCard, cfg store.NotifyConfig) string {
	if c.Stale {
		return "crit"
	}
	for _, i := range c.Interfaces {
		if i.Status == store.StatusGone {
			continue
		}
		if !i.UnitActive || (i.LastVerifyOK != nil && !*i.LastVerifyOK) {
			return "crit"
		}
	}
	if pctOf(c.Metric.DiskUsed, c.Metric.DiskTotal) >= cfg.DiskHigh {
		return "crit"
	}
	if c.RebootRequired || pctOf(c.Metric.MemUsed, c.Metric.MemTotal) >= cfg.MemHigh ||
		(cfg.LoadHigh > 0 && c.Metric.Load1 > cfg.LoadHigh) {
		return "warn"
	}
	// Наблюдаемый интерфейс в вердикт не входит: на каждой машине парка есть служебные
	// туннели под наблюдением, и от них сервер вечно выглядел бы «требующим внимания».
	for _, i := range c.Interfaces {
		if i.Status == store.StatusGone || i.Unassigned > 0 {
			return "warn"
		}
	}
	return "ok"
}

// fillCard считает всё, что карточке сервера нужно показать: фразу, уровень и три полосы.
// Уровень и пороги те же, что у оповещателя, — панель и бот обязаны говорить одно и то же.
func (s *Server) fillCard(c *serverCard, cfg store.NotifyConfig) {
	c.Say = s.say(*c)
	c.DiskPct = pctOf(c.Metric.DiskUsed, c.Metric.DiskTotal)
	c.MemPct = pctOf(c.Metric.MemUsed, c.Metric.MemTotal)
	if cfg.LoadHigh > 0 {
		c.LoadPct = min(int(c.Metric.Load1/cfg.LoadHigh*100), 100)
	}
	c.DiskLevel = overLevel(c.DiskPct, cfg.DiskHigh)
	c.MemLevel = overLevel(c.MemPct, cfg.MemHigh)
	if cfg.LoadHigh > 0 && c.Metric.Load1 > cfg.LoadHigh {
		c.LoadLvl = "warn"
	}
	c.Level = serverLevel(*c, cfg)
	switch {
	case c.Stale:
		c.LevelWord = "не отвечает"
	case c.Level == "crit":
		c.LevelWord = "поломка"
	case c.Level == "warn":
		c.LevelWord = "требует внимания"
	default:
		c.LevelWord = "в порядке"
	}
}

// overLevel — «warn» на подходе к порогу и «crit» за ним: полоса краснеет не внезапно.
func overLevel(pct, high int) string {
	switch {
	case high <= 0:
		return ""
	case pct >= high:
		return "crit"
	case pct >= high-15:
		return "warn"
	}
	return ""
}
