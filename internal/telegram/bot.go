package telegram

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/store"
)

// Reporter — то, что бот рассказывает по команде. Интерфейс живёт здесь, реализация — в хабе:
// так пакет оповещателя не тянет за собой хаб, а хаб не знает про Telegram.
type Reporter interface {
	StatusText(ctx context.Context) (string, error)
	OnlineText(ctx context.Context, arg string) (string, error)
	ServerText(ctx context.Context, slug string) (string, error)
}

// Окна антифлуда (SPEC FR-8.3).
const (
	// DigestWindow — сколько ждать похожие события, прежде чем слать. Критические не ждут.
	DigestWindow = 60 * time.Second
	// RepeatWindow — повтор того же состояния об одном объекте не чаще раза в час.
	RepeatWindow = time.Hour
	// pollTimeout — сколько держать соединение long polling.
	pollTimeout = 50 * time.Second
	// notifyEvery — как часто разбирается очередь событий.
	notifyEvery = 15 * time.Second
	// maxDigestLines — сколько строк показывать в дайджесте, остальные схлопываются в «и ещё N».
	maxDigestLines = 5
)

// Bot — оповещатель и отвечающий на команды чтения.
type Bot struct {
	Client *Client
	Store  *store.Store
	Log    *slog.Logger
	Report Reporter
	TZ     *time.Location
	Admins []int64

	// now подменяется в тестах: тихие часы и окна антифлуда завязаны на время.
	now func() time.Time

	lastSent   map[string]time.Time // ключ состояния → когда о нём говорили
	strangers  map[int64]time.Time  // чужие чаты → когда последний раз записали в журнал
	lastUpdate int64
}

// New собирает бота. TZ нужен для тихих часов и подписей времени.
func New(client *Client, st *store.Store, log *slog.Logger, rep Reporter, tz *time.Location, admins []int64) *Bot {
	if tz == nil {
		tz = time.UTC
	}
	return &Bot{Client: client, Store: st, Log: log, Report: rep, TZ: tz, Admins: admins,
		now: time.Now, lastSent: map[string]time.Time{}, strangers: map[int64]time.Time{}}
}

// Run поднимает оба цикла до отмены контекста: приём команд и рассылку событий.
func (b *Bot) Run(ctx context.Context) {
	me, err := b.Client.GetMe(ctx)
	if err != nil {
		b.Log.Error("telegram: бот не отвечает", "err", err)
		return
	}
	b.Log.Info("telegram: бот на связи", "bot", me.Username, "админов", len(b.Admins))
	// Вебхук и long polling взаимоисключающи: если вебхук остался от прошлого владельца токена,
	// getUpdates будет отвечать 409, и бот промолчит навсегда.
	if err := b.Client.DeleteWebhook(ctx); err != nil {
		b.Log.Warn("telegram: снятие вебхука", "err", err)
	}
	// Первый запуск: старую очередь не вываливаем в чат — только то, что произошло только что.
	if n, err := b.Store.SkipEventsBefore(ctx, b.now().Add(-DigestWindow)); err != nil {
		b.Log.Warn("telegram: очистка очереди", "err", err)
	} else if n > 0 {
		b.Log.Info("telegram: прошлые события пропущены", "n", n)
	}
	b.restoreOffset(ctx)
	go b.pollLoop(ctx)
	go b.notifyLoop(ctx)
}

// Send отправляет текст всем администраторам (используется бэкапом и разовыми сообщениями).
func (b *Bot) Send(ctx context.Context, text string) error {
	var firstErr error
	for _, id := range b.Admins {
		if err := b.Client.SendMessage(ctx, id, text); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// SendFile отправляет файл всем администраторам (бэкап, §6.9).
func (b *Bot) SendFile(ctx context.Context, name string, data []byte, caption string) error {
	var firstErr error
	for _, id := range b.Admins {
		if err := b.Client.SendDocument(ctx, id, name, data, caption); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ---------- рассылка событий ----------

func (b *Bot) notifyLoop(ctx context.Context) {
	t := time.NewTicker(notifyEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := b.Flush(ctx); err != nil {
				b.Log.Warn("telegram: рассылка", "err", err)
			}
		}
	}
}

// Flush разбирает очередь событий: выключенные виды и повторы гасит, остальное схлопывает
// по видам и отправляет. Экспортирован ради тестов и разовой отправки после действия.
func (b *Bot) Flush(ctx context.Context) error {
	cfg, err := b.Store.Notify(ctx)
	if err != nil {
		return err
	}
	events, err := b.Store.PendingEvents(ctx, 200)
	if err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	now := b.now()
	quiet := cfg.Quiet(now.In(b.TZ))

	var skip []int64                     // помечаем отправленными, ничего не посылая
	groups := map[string][]store.Event{} // вид → события к отправке
	var order []string
	for _, e := range events {
		crit := e.Severity == "crit"
		switch {
		case !cfg.Enabled, cfg.IsOff(e.Kind):
			skip = append(skip, e.ID)
			continue
		case b.suppressed(e, now):
			skip = append(skip, e.ID)
			continue
		case quiet && !crit:
			continue // подождёт конца тихих часов
		case !crit && now.Sub(e.TS) < DigestWindow:
			continue // ждём соседей того же вида
		}
		if _, ok := groups[e.Kind]; !ok {
			order = append(order, e.Kind)
		}
		groups[e.Kind] = append(groups[e.Kind], e)
	}
	if err := b.Store.MarkNotified(ctx, skip, now); err != nil {
		return err
	}
	sort.Strings(order)
	for _, kind := range order {
		group := groups[kind]
		text := b.format(group)
		if err := b.Send(ctx, text); err != nil {
			var apiErr *Error
			// 4xx (кроме «слишком часто») не пройдёт и со второй попытки: чат удалён, бот
			// заблокирован. Возвращать такое событие в очередь — копить её вечно.
			if errors.As(err, &apiErr) && apiErr.Code >= 400 && apiErr.Code < 500 && apiErr.RetryAfter == 0 {
				b.Log.Warn("telegram: сообщение отклонено", "kind", kind, "err", err)
				b.Store.MarkNotified(ctx, ids(group), now)
				continue
			}
			return err
		}
		for _, e := range group {
			b.lastSent[stateKey(e)] = now
		}
		if err := b.Store.MarkNotified(ctx, ids(group), now); err != nil {
			return err
		}
	}
	return nil
}

// suppressed — говорили ли о том же состоянии того же объекта меньше часа назад.
func (b *Bot) suppressed(e store.Event, now time.Time) bool {
	last, ok := b.lastSent[stateKey(e)]
	return ok && now.Sub(last) < RepeatWindow
}

func stateKey(e store.Event) string {
	return fmt.Sprintf("%s/%d/%d/%d", e.Kind, e.InterfaceID, e.DeviceID, e.UserID)
}

func ids(events []store.Event) []int64 {
	out := make([]int64, 0, len(events))
	for _, e := range events {
		out = append(out, e.ID)
	}
	return out
}

// format собирает сообщение по группе событий одного вида: одно — строкой, несколько — дайджестом.
func (b *Bot) format(group []store.Event) string {
	head := icon(group[0].Severity)
	when := group[len(group)-1].TS.In(b.TZ).Format("02.01 15:04")
	if len(group) == 1 {
		return fmt.Sprintf("%s <b>%s</b>\n<i>%s · %s</i>", head, Esc(group[0].Message), when, Esc(kindTitle(group[0].Kind)))
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s <b>%s — %d</b>\n", head, Esc(kindTitle(group[0].Kind)), len(group))
	for i, e := range group {
		if i == maxDigestLines {
			fmt.Fprintf(&sb, "…и ещё %d\n", len(group)-maxDigestLines)
			break
		}
		fmt.Fprintf(&sb, "• %s\n", Esc(e.Message))
	}
	fmt.Fprintf(&sb, "<i>%s</i>", when)
	return sb.String()
}

func icon(severity string) string {
	switch severity {
	case "crit":
		return "🔴"
	case "warn":
		return "⚠️"
	default:
		return "ℹ️"
	}
}

// kindTitle — человеческое название вида события; неизвестный вид показывается как есть.
func kindTitle(kind string) string {
	if t, ok := kindTitles[kind]; ok {
		return t
	}
	return kind
}

var kindTitles = map[string]string{
	"node_down":           "узел не отвечает",
	"node_up":             "узел вернулся",
	"iface_down":          "интерфейс упал",
	"iface_up":            "интерфейс поднялся",
	"iface_endpoint":      "endpoint по умолчанию",
	"handshake_drought":   "засуха хендшейков",
	"device_first_online": "первое подключение устройства",
	"device_created":      "устройство создано",
	"device_deleted":      "устройство удалено",
	"device_keys_rotated": "ключи перевыпущены",
	"self_service_device": "устройство создано по ссылке",
	"self_service_rename": "устройство переименовано по ссылке",
	"self_service_delete": "устройство удалено по ссылке",
	"user_created":        "пользователь создан",
	"user_deleted":        "пользователь удалён",
	"user_restored":       "пользователь восстановлен",
	"user_expired":        "срок пользователя истёк",
	"user_link_reissued":  "ссылка перевыпущена",
	"users_merged":        "пользователи объединены",
	"disk_high":           "мало места на диске",
	"disk_ok":             "место на диске в норме",
	"mem_high":            "мало памяти",
	"mem_ok":              "память в норме",
	"load_high":           "высокая нагрузка",
	"load_ok":             "нагрузка в норме",
	"traffic_spike":       "всплеск трафика",
	"backup_ok":           "бэкап готов",
	"backup_failed":       "бэкап не сделан",
	"panel_started":       "панель запущена",
	"panel_stopped":       "панель остановлена",
	"guard":               "запись отклонена охраной",
	"verify_failed":       "обфускация разошлась",
	"verify_ok":           "обфускация совпала",
	"counters_reset":      "счётчики сброшены",
	"interface_mode":      "режим интерфейса изменён",
	"tg_stranger":         "посторонний в боте",
	"purge":               "корзина очищена",
}

// ---------- команды ----------

func (b *Bot) pollLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		ups, err := b.Client.GetUpdates(ctx, b.lastUpdate+1, pollTimeout)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			var apiErr *Error
			wait := 5 * time.Second
			if errors.As(err, &apiErr) && apiErr.RetryAfter > 0 {
				wait = apiErr.RetryAfter
			}
			b.Log.Warn("telegram: опрос", "err", err, "пауза", wait)
			select {
			case <-ctx.Done():
				return
			case <-time.After(wait):
			}
			continue
		}
		for _, u := range ups {
			if u.ID > b.lastUpdate {
				b.lastUpdate = u.ID
			}
			if u.Message != nil {
				b.handle(ctx, u.Message)
			}
		}
		if len(ups) > 0 {
			b.saveOffset(ctx)
		}
	}
}

// handle отвечает на команду, если чат в whitelist; постороннему — молчание и запись в журнал
// (FR-8.1). Молчание намеренное: бот не подтверждает чужому, что он вообще существует.
func (b *Bot) handle(ctx context.Context, m *Message) {
	if !b.allowed(m.From.ID) && !b.allowed(m.Chat.ID) {
		b.noteStranger(ctx, m)
		return
	}
	text, err := b.answer(ctx, strings.TrimSpace(m.Text))
	if err != nil {
		b.Log.Warn("telegram: команда", "text", m.Text, "err", err)
		text = "не получилось: " + Esc(err.Error())
	}
	if text == "" {
		return
	}
	if err := b.Client.SendMessage(ctx, m.Chat.ID, text); err != nil {
		b.Log.Warn("telegram: ответ", "err", err)
	}
}

func (b *Bot) answer(ctx context.Context, text string) (string, error) {
	cmd, arg, _ := strings.Cut(text, " ")
	cmd = strings.ToLower(strings.TrimSpace(cmd))
	// Команда в группе приходит с суффиксом бота: /status@awgdash_bot.
	if i := strings.IndexByte(cmd, '@'); i > 0 {
		cmd = cmd[:i]
	}
	arg = strings.TrimSpace(arg)
	switch cmd {
	case "/start", "/help":
		return helpText, nil
	case "/status":
		return b.Report.StatusText(ctx)
	case "/online":
		return b.Report.OnlineText(ctx, arg)
	case "/server":
		return b.Report.ServerText(ctx, arg)
	default:
		if strings.HasPrefix(cmd, "/") {
			return "не знаю такой команды\n" + helpText, nil
		}
		return "", nil // обычный текст — не команда, отвечать нечего
	}
}

const helpText = "<b>Что умею</b>\n" +
	"/status — все серверы одной строкой\n" +
	"/online [сервер] — кто сейчас на связи\n" +
	"/server &lt;slug&gt; — подробности по серверу\n" +
	"/help — эта справка\n\n" +
	"Изменения — только через панель: бот читает, но не правит."

func (b *Bot) allowed(id int64) bool {
	for _, a := range b.Admins {
		if a == id {
			return true
		}
	}
	return false
}

// noteStranger пишет в журнал факт чужого обращения, но не чаще раза в час на отправителя:
// иначе бот, найденный перебором, забьёт журнал.
func (b *Bot) noteStranger(ctx context.Context, m *Message) {
	now := b.now()
	if last, ok := b.strangers[m.From.ID]; ok && now.Sub(last) < RepeatWindow {
		return
	}
	b.strangers[m.From.ID] = now
	who := m.From.Username
	if who == "" {
		who = m.From.Name
	}
	msg := fmt.Sprintf("посторонний %d (%s) написал боту: %s", m.From.ID, who, trim(m.Text, 120))
	b.Store.AddEvent(ctx, store.Event{Kind: "tg_stranger", Severity: "warn", Message: msg})
	b.Log.Warn("telegram: посторонний", "id", m.From.ID, "user", who)
}

// offset обновлений переживает перезапуск: иначе после рестарта панель ответит на уже
// обработанные команды заново.
const offsetKey = "tg_offset"

func (b *Bot) restoreOffset(ctx context.Context) {
	raw, err := b.Store.Setting(ctx, offsetKey)
	if err != nil || raw == "" {
		return
	}
	if v, err := strconv.ParseInt(raw, 10, 64); err == nil {
		b.lastUpdate = v
	}
}

func (b *Bot) saveOffset(ctx context.Context) {
	if err := b.Store.SetSetting(ctx, offsetKey, strconv.FormatInt(b.lastUpdate, 10)); err != nil {
		b.Log.Warn("telegram: сохранение offset", "err", err)
	}
}
