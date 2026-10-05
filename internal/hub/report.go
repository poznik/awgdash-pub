package hub

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/humanize"
	"github.com/poznik/awgdash-pub/internal/store"
	"github.com/poznik/awgdash-pub/internal/telegram"
)

// Отчёты для бота (SPEC FR-8.4). Хаб реализует telegram.Reporter; разметка — HTML, как её
// понимает Bot API. Всё, что пришло от человека (имена), экранируется.
var _ telegram.Reporter = (*Hub)(nil)

// speedWindow — на каком окне считать «сейчас»: минуты хватает, чтобы всплеск не пропал,
// и достаточно, чтобы цифра не прыгала от одной выборки.
const speedWindow = time.Minute

// StatusText — все серверы одной строкой каждый: онлайн, скорость, диск, нагрузка.
func (h *Hub) StatusText(ctx context.Context) (string, error) {
	servers, err := h.Store.Servers(ctx)
	if err != nil {
		return "", err
	}
	if len(servers) == 0 {
		return "серверов нет", nil
	}
	st := h.Status()
	var sb strings.Builder
	for _, srv := range servers {
		peers, online := 0, 0
		for name, n := range st.Peers {
			_ = name
			peers += n
		}
		for _, n := range st.Online {
			online += n
		}
		fmt.Fprintf(&sb, "<b>%s</b> · онлайн %d из %d\n", telegram.Esc(srv.Slug), online, peers)

		ids, err := h.serverPeerIDs(ctx, srv.ID)
		if err != nil {
			return "", err
		}
		if sp, err := h.Store.PeerSpeed(ctx, ids, speedWindow); err == nil && (sp.RxBps > 0 || sp.TxBps > 0) {
			fmt.Fprintf(&sb, "↓ %s ↑ %s\n", humanize.Bps(sp.RxBps), humanize.Bps(sp.TxBps))
		}
		if m, ok := h.lastMetric(ctx, srv.ID); ok {
			fmt.Fprintf(&sb, "диск %s · память %s · load %.2f · аптайм %s\n",
				humanize.Pct(m.DiskUsed, m.DiskTotal), humanize.Pct(m.MemUsed, m.MemTotal), m.Load1, humanize.Dur(h.uptime(ctx)))
		}
		ifaces, err := h.Store.Interfaces(ctx, srv.ID)
		if err != nil {
			return "", err
		}
		for _, i := range ifaces {
			fmt.Fprintf(&sb, "%s · %s · %s · %s\n", telegram.Esc(i.Name), i.Mode, unitWord(i.UnitActive), verifyWord(i.LastVerifyOK))
		}
	}
	sb.WriteString("<i>обновлено " + time.Now().In(h.tz()).Format("15:04:05") + "</i>")
	return sb.String(), nil
}

// OnlineText — кто сейчас на связи. Аргумент фильтрует по серверу или интерфейсу.
func (h *Hub) OnlineText(ctx context.Context, arg string) (string, error) {
	servers, err := h.Store.Servers(ctx)
	if err != nil {
		return "", err
	}
	arg = strings.ToLower(strings.TrimSpace(arg))
	type row struct {
		device, user, iface string
		rx, tx              uint64
		since               time.Duration
	}
	var rows []row
	for _, srv := range servers {
		if arg != "" && !strings.EqualFold(srv.Slug, arg) && !strings.HasPrefix(arg, "awg") {
			continue
		}
		ifaces, err := h.Store.Interfaces(ctx, srv.ID)
		if err != nil {
			return "", err
		}
		for _, i := range ifaces {
			if arg != "" && strings.HasPrefix(arg, "awg") && !strings.EqualFold(i.Name, arg) {
				continue
			}
			devices, err := h.Store.DevicesByInterface(ctx, i.ID, true)
			if err != nil {
				return "", err
			}
			peers, err := h.Store.Peers(ctx, i.ID, false)
			if err != nil {
				return "", err
			}
			ids := make([]int64, 0, len(peers))
			for _, p := range peers {
				ids = append(ids, p.ID)
			}
			speeds, err := h.Store.PeerSpeeds(ctx, ids, speedWindow)
			if err != nil {
				return "", err
			}
			named := map[int64]bool{}
			for _, d := range devices {
				named[d.PeerID] = true
				if !d.Online() {
					continue
				}
				sp := speeds[d.PeerID]
				rows = append(rows, row{device: d.Name, user: d.UserName, iface: i.Name, rx: sp.RxBps, tx: sp.TxBps, since: time.Since(d.LastHandshake)})
			}
			// Пиры без устройства (импорт не разобрал, правили конфиг руками) тоже видны:
			// «онлайн 5» в /status и пустой /online противоречили бы друг другу.
			for _, p := range peers {
				if named[p.ID] {
					continue
				}
				if label, _ := PeerState(p.LastHandshake, time.Now()); label != "онлайн" {
					continue
				}
				sp := speeds[p.ID]
				rows = append(rows, row{device: p.PublicKey[:8] + "…", iface: i.Name, rx: sp.RxBps, tx: sp.TxBps, since: time.Since(p.LastHandshake)})
			}
		}
	}
	if len(rows) == 0 {
		return "сейчас никого", nil
	}
	sort.Slice(rows, func(a, b int) bool { return rows[a].rx+rows[a].tx > rows[b].rx+rows[b].tx })
	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>На связи: %d</b>\n", len(rows))
	for _, r := range rows {
		who := r.user
		if who == "" {
			who = "без владельца"
		}
		fmt.Fprintf(&sb, "• %s · %s · %s · ↓%s ↑%s\n", telegram.Esc(r.device), telegram.Esc(who), telegram.Esc(r.iface), humanize.Bps(r.rx), humanize.Bps(r.tx))
	}
	return strings.TrimRight(sb.String(), "\n"), nil
}

// ServerText — подробности по серверу: метрики, версии, интерфейсы, итоги за сутки.
func (h *Hub) ServerText(ctx context.Context, slug string) (string, error) {
	servers, err := h.Store.Servers(ctx)
	if err != nil {
		return "", err
	}
	if len(servers) == 0 {
		return "серверов нет", nil
	}
	srv := servers[0]
	if slug != "" {
		found := false
		for _, s := range servers {
			if strings.EqualFold(s.Slug, slug) {
				srv, found = s, true
				break
			}
		}
		if !found {
			names := make([]string, 0, len(servers))
			for _, s := range servers {
				names = append(names, s.Slug)
			}
			return "нет такого сервера; есть: " + telegram.Esc(strings.Join(names, ", ")), nil
		}
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "<b>%s</b>\n", telegram.Esc(srv.Slug))
	if m, ok := h.lastMetric(ctx, srv.ID); ok {
		fmt.Fprintf(&sb, "cpu %.0f%% · память %s из %s · диск %s из %s\nload %.2f · аптайм %s\n",
			m.CPU, humanize.Bytes(m.MemUsed), humanize.Bytes(m.MemTotal),
			humanize.Bytes(m.DiskUsed), humanize.Bytes(m.DiskTotal), m.Load1, humanize.Dur(h.uptime(ctx)))
	}
	if srv.PublicIP != "" {
		fmt.Fprintf(&sb, "адрес %s · ядро %s\n", telegram.Esc(srv.PublicIP), telegram.Esc(srv.Kernel))
	}
	fmt.Fprintf(&sb, "awg %s · панель %s\n", telegram.Esc(srv.AWGVersion), telegram.Esc(srv.AwgdashVersion))

	ids, err := h.serverPeerIDs(ctx, srv.ID)
	if err != nil {
		return "", err
	}
	if t, err := h.Store.PeerTotals(ctx, ids); err == nil {
		fmt.Fprintf(&sb, "за сутки ↓%s ↑%s · за месяц ↓%s ↑%s\n",
			humanize.Bytes(t.DayRx), humanize.Bytes(t.DayTx), humanize.Bytes(t.MonthRx), humanize.Bytes(t.MonthTx))
	}
	ifaces, err := h.Store.Interfaces(ctx, srv.ID)
	if err != nil {
		return "", err
	}
	st := h.Status()
	for _, i := range ifaces {
		fmt.Fprintf(&sb, "\n<b>%s</b> · %s · %s · %s\nустройств %d, онлайн %d · порт %d · MTU %d",
			telegram.Esc(i.Name), i.Mode, unitWord(i.UnitActive), verifyWord(i.LastVerifyOK),
			st.Peers[i.ID], st.Online[i.ID], i.ListenPort, i.MTU)
	}
	if fm := h.ForeignManager(); fm != "" {
		fmt.Fprintf(&sb, "\n⚠️ активен чужой менеджер пиров: %s", telegram.Esc(fm))
	}
	return sb.String(), nil
}

// serverPeerIDs — все пиры сервера (по всем его интерфейсам).
func (h *Hub) serverPeerIDs(ctx context.Context, serverID int64) ([]int64, error) {
	ifaces, err := h.Store.Interfaces(ctx, serverID)
	if err != nil {
		return nil, err
	}
	var out []int64
	for _, i := range ifaces {
		ids, err := h.Store.InterfacePeerIDs(ctx, i.ID)
		if err != nil {
			return nil, err
		}
		out = append(out, ids...)
	}
	return out, nil
}

func (h *Hub) lastMetric(ctx context.Context, serverID int64) (store.HostMetric, bool) {
	ms, err := h.Store.HostMetrics(ctx, serverID, time.Now().Add(-15*time.Minute))
	if err != nil || len(ms) == 0 {
		return store.HostMetric{}, false
	}
	return ms[len(ms)-1], true
}

// uptime берётся у сборщика метрик: в БД он не хранится, а для строки статуса нужен свежий.
func (h *Hub) uptime(ctx context.Context) time.Duration {
	local, err := h.Agent(h.ServerID)
	if err != nil {
		return 0
	}
	s, err := local.HostMetrics(ctx)
	if err != nil || !s.Supported {
		return 0
	}
	return time.Duration(s.UptimeSeconds) * time.Second
}

func (h *Hub) tz() *time.Location {
	if loc, err := time.LoadLocation(h.Cfg.TZ); err == nil {
		return loc
	}
	return time.UTC
}

func unitWord(active bool) string {
	if active {
		return "юнит активен"
	}
	return "юнит неактивен"
}

// verifyWord: сверки могло ещё не быть — «неизвестно» честнее, чем «расходится».
func verifyWord(ok *bool) string {
	switch {
	case ok == nil:
		return "обфускация не сверялась"
	case *ok:
		return "обфускация 12/12"
	default:
		return "обфускация расходится"
	}
}
