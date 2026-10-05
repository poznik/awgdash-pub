package hub

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/poznik/awgdash-pub/internal/hostmetrics"
	"github.com/poznik/awgdash-pub/internal/humanize"
	"github.com/poznik/awgdash-pub/internal/store"
	"github.com/poznik/awgdash-pub/internal/telegram"
	"github.com/poznik/awgdash-pub/internal/version"
)

// Тревоги по порогам и наблюдению за интерфейсами (SPEC FR-8.2). Каждая проверка знает
// своё предыдущее состояние: событие пишется на переходе, а не каждую минуту.

const (
	// hysteresis — на сколько процентных пунктов надо опуститься, чтобы объявить «в норме».
	// Без запаса значение, колеблющееся у порога, породило бы поток сообщений.
	hysteresis = 5
	// nodeDownAfter — сколько неудачных выборок подряд терпим, прежде чем сказать «узел не отвечает».
	nodeDownAfter = 2 * time.Minute
	// droughtWindow — сколько тишины на интерфейсе считать засухой хендшейков.
	droughtWindow = 15 * time.Minute
	// spikeWindow — окно, за которое считается всплеск трафика.
	spikeWindow = time.Hour
)

// checkThresholds сравнивает свежий снимок с порогами и пишет переходы в обе стороны.
// Считается по каждому серверу парка: полный диск на удалённом узле так же опасен, как на своём.
func (h *Hub) checkThresholds(ctx context.Context, srv *Server, s hostmetrics.Snapshot) {
	cfg, err := h.Store.Notify(ctx)
	if err != nil {
		h.Log.Warn("настройки оповещателя", "err", err)
		return
	}
	// Имя сервера в сообщении нужно, только когда серверов больше одного: иначе это шум.
	where := ""
	if len(h.servers.all()) > 1 {
		where = srv.Slug + ": "
	}
	disk := humanize.Percent(s.DiskUsed, s.DiskTotal)
	mem := humanize.Percent(s.MemUsed, s.MemTotal)
	h.threshold(ctx, srv, "disk", float64(disk), float64(cfg.DiskHigh),
		fmt.Sprintf("%sдиск занят на %d %% (%s из %s)", where, disk, humanize.Bytes(s.DiskUsed), humanize.Bytes(s.DiskTotal)),
		fmt.Sprintf("%sместо на диске вернулось в норму: %d %%", where, disk))
	h.threshold(ctx, srv, "mem", float64(mem), float64(cfg.MemHigh),
		fmt.Sprintf("%sпамять занята на %d %% (%s из %s)", where, mem, humanize.Bytes(s.MemUsed), humanize.Bytes(s.MemTotal)),
		fmt.Sprintf("%sпамять вернулась в норму: %d %%", where, mem))
	h.threshold(ctx, srv, "load", s.Load1, cfg.LoadHigh,
		fmt.Sprintf("%sнагрузка %.2f за минуту", where, s.Load1),
		fmt.Sprintf("%sнагрузка вернулась в норму: %.2f", where, s.Load1))
}

// threshold — общая механика: сработало выше порога, отпустило ниже порога с запасом.
func (h *Hub) threshold(ctx context.Context, srv *Server, name string, value, limit float64, highMsg, okMsg string) {
	if limit <= 0 {
		return
	}
	key := name + "/" + srv.Slug
	h.mu.Lock()
	was := h.alerts[key]
	now := was
	switch {
	case value >= limit:
		now = true
	case value < limit-hysteresis:
		now = false
	}
	h.alerts[key] = now
	h.mu.Unlock()
	if now == was {
		return
	}
	if now {
		h.eventOn(ctx, srv.ID, name+"_high", "warn", 0, 0, highMsg)
	} else {
		h.eventOn(ctx, srv.ID, name+"_ok", "info", 0, 0, okMsg)
	}
}

// markAlert запоминает состояние тревоги и говорит, изменилось ли оно. Нужен там, где
// проверка повторяется чаще, чем меняется положение дел: событие пишется на переходе.
func (h *Hub) markAlert(key string, on bool) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.alerts[key] == on {
		return false
	}
	h.alerts[key] = on
	return true
}

// noteSampleResult отмечает удачу или неудачу обхода: узел, который не отвечает дольше двух
// минут, — событие, а мгновенная ошибка сети — нет.
func (h *Hub) noteSampleResult(ctx context.Context, err error) {
	h.mu.Lock()
	if err == nil {
		wasDown := h.nodeDown
		h.nodeDown, h.sampleFailedAt = false, time.Time{}
		h.mu.Unlock()
		if wasDown {
			h.event(ctx, "node_up", "info", 0, 0, "узел снова отвечает")
		}
		return
	}
	if h.sampleFailedAt.IsZero() {
		h.sampleFailedAt = time.Now()
	}
	down := !h.nodeDown && time.Since(h.sampleFailedAt) >= nodeDownAfter
	if down {
		h.nodeDown = true
	}
	h.mu.Unlock()
	if down {
		h.event(ctx, "node_down", "crit", 0, 0, "узел не отвечает: "+err.Error())
	}
}

// noteFirstOnline сообщает о первом в жизни хендшейке устройства (FR-8.2).
func (h *Hub) noteFirstOnline(ctx context.Context, serverID, ifaceID int64, peerIDs []int64) {
	if len(peerIDs) == 0 {
		return
	}
	devices, err := h.Store.DevicesByPeerIDs(ctx, peerIDs)
	if err != nil {
		h.Log.Warn("первое подключение", "err", err)
		return
	}
	for _, d := range devices {
		who := d.UserName
		if who == "" {
			who = "без владельца"
		}
		h.eventOn(ctx, serverID, "device_first_online", "info", ifaceID, d.ID,
			fmt.Sprintf("устройство «%s» (%s) подключилось впервые", d.Name, who))
	}
}

// checkDrought ищет засуху хендшейков: сервер жив, устройства есть, а рукопожатий нет
// четверть часа — обычно так выглядит блокировка адреса (FR-8.2, сценарий S4).
func (h *Hub) checkDrought(ctx context.Context) error {
	cfg, err := h.Store.Notify(ctx)
	if err != nil {
		return err
	}
	ifaces, err := h.Store.Interfaces(ctx, h.ServerID)
	if err != nil {
		return err
	}
	for _, i := range ifaces {
		if !i.UnitActive {
			continue // о лежащем интерфейсе уже сказано отдельным событием
		}
		peers, err := h.Store.Peers(ctx, i.ID, false)
		if err != nil {
			return err
		}
		active, fresh := 0, 0
		var last time.Time
		for _, p := range peers {
			if p.LastHandshake.IsZero() {
				continue
			}
			if time.Since(p.LastHandshake) <= 24*time.Hour {
				active++
			}
			if time.Since(p.LastHandshake) <= droughtWindow {
				fresh++
			}
			if p.LastHandshake.After(last) {
				last = p.LastHandshake
			}
		}
		key := "drought/" + i.Name
		dry := active >= cfg.DroughtMin && fresh == 0
		h.mu.Lock()
		was := h.alerts[key]
		h.alerts[key] = dry
		h.mu.Unlock()
		if dry == was {
			continue
		}
		if dry {
			h.event(ctx, "handshake_drought", "crit", i.ID, 0,
				fmt.Sprintf("%s: за сутки было %d устройств, но %s нет ни одного хендшейка — похоже на блокировку адреса",
					i.Name, active, humanize.Dur(time.Since(last))))
		} else {
			h.event(ctx, "handshake_drought_ok", "info", i.ID, 0, i.Name+": хендшейки снова идут")
		}
	}
	return nil
}

// checkSpikes отмечает устройства, вылившие за час больше порога (FR-8.2).
func (h *Hub) checkSpikes(ctx context.Context) error {
	cfg, err := h.Store.Notify(ctx)
	if err != nil {
		return err
	}
	if cfg.SpikeGB <= 0 {
		return nil
	}
	limit := uint64(cfg.SpikeGB * 1e9)
	ifaces, err := h.Store.Interfaces(ctx, h.ServerID)
	if err != nil {
		return err
	}
	for _, i := range ifaces {
		devices, err := h.Store.DevicesByInterface(ctx, i.ID, false)
		if err != nil {
			return err
		}
		peerIDs := make([]int64, 0, len(devices))
		byPeer := map[int64]store.Device{}
		for _, d := range devices {
			if d.PeerID == 0 {
				continue
			}
			peerIDs = append(peerIDs, d.PeerID)
			byPeer[d.PeerID] = d
		}
		traffic, err := h.Store.TrafficSince(ctx, peerIDs, time.Now().Add(-spikeWindow))
		if err != nil {
			return err
		}
		for peerID, v := range traffic {
			total := v[0] + v[1]
			if total < limit {
				continue
			}
			d := byPeer[peerID]
			who := d.UserName
			if who == "" {
				who = "без владельца"
			}
			// Повтор гасит сам оповещатель (не чаще раза в час об одном объекте), поэтому
			// здесь достаточно писать событие при каждом превышении.
			h.event(ctx, "traffic_spike", "warn", i.ID, d.ID,
				fmt.Sprintf("«%s» (%s) прокачало %s за час", d.Name, who, humanize.Bytes(total)))
		}
	}
	return nil
}

// alertsLoop — редкие проверки, которым не нужен темп выборки.
func (h *Hub) alertsLoop(ctx context.Context) error {
	if err := h.checkDrought(ctx); err != nil {
		return err
	}
	return h.checkSpikes(ctx)
}

// NotifyStopped прощается перед остановкой: очередь разбирается раз в пятнадцать секунд,
// а процесс уходит сейчас — поэтому сообщение отправляется напрямую, минуя очередь.
func (h *Hub) NotifyStopped(log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	msg := "панель остановлена · " + version.Version
	h.event(ctx, "panel_stopped", "warn", 0, 0, msg)
	if h.Bot == nil {
		return
	}
	if err := h.Bot.Send(ctx, "⚠️ <b>"+telegram.Esc(msg)+"</b>"); err != nil {
		log.Warn("прощальное сообщение", "err", err)
	}
	// То, что не успело уйти, уже не уйдёт: помечаем очередь, чтобы после перезапуска
	// не получить пачку сообщений о прошлой жизни.
	if _, err := h.Store.SkipEventsBefore(ctx, time.Now()); err != nil {
		log.Warn("закрытие очереди событий", "err", err)
	}
}
