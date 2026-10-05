package telegram

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/poznik/awgdash-pub/internal/store"
)

// fakeAPI — Bot API на httptest: запоминает отправленное и отвечает так, как настроено.
type fakeAPI struct {
	srv   *httptest.Server
	sent  []map[string]any
	fail  int    // код ошибки, если не ноль
	descr string // описание ошибки
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		json.Unmarshal(body, &payload)
		method := r.URL.Path[strings.LastIndexByte(r.URL.Path, '/')+1:]
		payload["_method"] = method
		f.sent = append(f.sent, payload)
		w.Header().Set("Content-Type", "application/json")
		if f.fail != 0 {
			w.Write([]byte(`{"ok":false,"error_code":` + itoa(f.fail) + `,"description":"` + f.descr + `"}`))
			return
		}
		switch method {
		case "getMe":
			w.Write([]byte(`{"ok":true,"result":{"id":1,"username":"testbot"}}`))
		case "getUpdates":
			w.Write([]byte(`{"ok":true,"result":[]}`))
		default:
			w.Write([]byte(`{"ok":true,"result":true}`))
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func (f *fakeAPI) texts() []string {
	var out []string
	for _, m := range f.sent {
		if m["_method"] == "sendMessage" {
			out = append(out, m["text"].(string))
		}
	}
	return out
}

func newTestBot(t *testing.T, f *fakeAPI, rep Reporter) (*Bot, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	c := NewClient("TOKEN")
	c.API = f.srv.URL
	c.HTTP = f.srv.Client()
	b := New(c, st, slog.New(slog.DiscardHandler), rep, time.UTC, []int64{42})
	return b, st
}

type stubReporter struct{ status, online, server string }

func (s stubReporter) StatusText(context.Context) (string, error)         { return s.status, nil }
func (s stubReporter) OnlineText(context.Context, string) (string, error) { return s.online, nil }
func (s stubReporter) ServerText(context.Context, string) (string, error) { return s.server, nil }

func TestSendMessageSplitsLongText(t *testing.T) {
	f := newFakeAPI(t)
	c := NewClient("T")
	c.API, c.HTTP = f.srv.URL, f.srv.Client()
	long := strings.TrimSuffix(strings.Repeat("строка длиной под сотню байт, чтобы набрать объём быстрее\n", 200), "\n")
	if err := c.SendMessage(context.Background(), 1, long); err != nil {
		t.Fatal(err)
	}
	if len(f.texts()) < 2 {
		t.Fatalf("длинный текст ушёл одним куском: %d частей", len(f.texts()))
	}
	for _, part := range f.texts() {
		if len(part) > MaxMessage {
			t.Fatalf("часть длиннее лимита: %d", len(part))
		}
	}
}

func TestAPIErrorHasCode(t *testing.T) {
	f := newFakeAPI(t)
	f.fail, f.descr = 401, "Unauthorized"
	c := NewClient("T")
	c.API, c.HTTP = f.srv.URL, f.srv.Client()
	_, err := c.GetMe(context.Background())
	apiErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("ожидалась *Error, получено %T (%v)", err, err)
	}
	if apiErr.Code != 401 {
		t.Fatalf("код %d, ожидался 401", apiErr.Code)
	}
}

// События одного вида схлопываются в дайджест, а не летят по одному (FR-8.3).
func TestFlushDigest(t *testing.T) {
	f := newFakeAPI(t)
	b, st := newTestBot(t, f, stubReporter{})
	ctx := context.Background()
	old := time.Now().Add(-2 * DigestWindow)
	for i := 0; i < 3; i++ {
		// Разные устройства: иначе сработает подавление повтора об одном объекте.
		if err := st.AddEvent(ctx, store.Event{Kind: "device_first_online", TS: old, DeviceID: int64(i + 1), Message: "устройство подключилось"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	texts := f.texts()
	if len(texts) != 1 {
		t.Fatalf("ожидалось одно сообщение-дайджест, отправлено %d: %v", len(texts), texts)
	}
	if !strings.Contains(texts[0], "— 3") {
		t.Fatalf("в дайджесте нет счётчика: %q", texts[0])
	}
	// Очередь должна закрыться: второй разбор ничего не шлёт.
	f.sent = nil
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.texts()) != 0 {
		t.Fatalf("события отправлены повторно: %v", f.texts())
	}
}

// Свежие некритические события ждут окна дайджеста, критические уходят сразу (FR-8.3).
func TestFlushWaitsForFreshInfoButNotCrit(t *testing.T) {
	f := newFakeAPI(t)
	b, st := newTestBot(t, f, stubReporter{})
	ctx := context.Background()
	if err := st.AddEvent(ctx, store.Event{Kind: "device_created", Message: "устройство создано"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.texts()) != 0 {
		t.Fatalf("свежее info ушло, не дождавшись соседей: %v", f.texts())
	}
	if err := st.AddEvent(ctx, store.Event{Kind: "iface_down", Severity: "crit", Message: "интерфейс упал"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.texts()) != 1 || !strings.Contains(f.texts()[0], "интерфейс упал") {
		t.Fatalf("критическое событие не ушло сразу: %v", f.texts())
	}
}

// Тихие часы придерживают обычные события и пропускают критические (FR-8.3).
func TestQuietHours(t *testing.T) {
	f := newFakeAPI(t)
	b, st := newTestBot(t, f, stubReporter{})
	ctx := context.Background()
	cfg := store.DefaultNotify()
	cfg.QuietEnabled, cfg.QuietFrom, cfg.QuietTo = true, 23, 8
	if err := st.SetNotify(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	night := time.Date(2026, 8, 24, 2, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return night }
	st.AddEvent(ctx, store.Event{Kind: "device_created", TS: night.Add(-2 * DigestWindow), Message: "устройство создано"})
	st.AddEvent(ctx, store.Event{Kind: "iface_down", Severity: "crit", TS: night, Message: "интерфейс упал"})
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	texts := f.texts()
	if len(texts) != 1 || !strings.Contains(texts[0], "интерфейс упал") {
		t.Fatalf("ночью должно уйти только критическое: %v", texts)
	}
	// Утром придержанное уходит.
	f.sent = nil
	b.now = func() time.Time { return time.Date(2026, 8, 24, 9, 0, 0, 0, time.UTC) }
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.texts()) != 1 || !strings.Contains(f.texts()[0], "устройство создано") {
		t.Fatalf("придержанное событие не ушло утром: %v", f.texts())
	}
}

// Повтор об одном и том же состоянии — не чаще раза в час (FR-8.3).
func TestRepeatSuppressed(t *testing.T) {
	f := newFakeAPI(t)
	b, st := newTestBot(t, f, stubReporter{})
	ctx := context.Background()
	add := func() {
		st.AddEvent(ctx, store.Event{Kind: "guard", Severity: "warn", InterfaceID: 1, TS: time.Now().Add(-2 * DigestWindow), Message: "запись отклонена"})
	}
	add()
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	f.sent = nil
	add()
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.texts()) != 0 {
		t.Fatalf("повтор ушёл раньше часа: %v", f.texts())
	}
	// Через час о том же можно сказать снова.
	b.now = func() time.Time { return time.Now().Add(RepeatWindow + time.Minute) }
	add()
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.texts()) != 1 {
		t.Fatalf("через час повтор должен пройти: %v", f.texts())
	}
}

// Выключенный вид события не отправляется, но и не копится в очереди.
func TestDisabledKind(t *testing.T) {
	f := newFakeAPI(t)
	b, st := newTestBot(t, f, stubReporter{})
	ctx := context.Background()
	cfg := store.DefaultNotify()
	cfg.Off = []string{"device_created"}
	st.SetNotify(ctx, cfg)
	st.AddEvent(ctx, store.Event{Kind: "device_created", TS: time.Now().Add(-2 * DigestWindow), Message: "устройство создано"})
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.texts()) != 0 {
		t.Fatalf("выключенный вид отправлен: %v", f.texts())
	}
	pending, err := st.PendingEvents(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("выключенное событие осталось в очереди: %d", len(pending))
	}
}

// Постороннему бот не отвечает, но записывает попытку в журнал (FR-8.1).
func TestStrangerGetsSilence(t *testing.T) {
	f := newFakeAPI(t)
	b, st := newTestBot(t, f, stubReporter{status: "всё хорошо"})
	ctx := context.Background()
	m := &Message{Text: "/status"}
	m.From.ID, m.Chat.ID = 999, 999
	b.handle(ctx, m)
	if len(f.texts()) != 0 {
		t.Fatalf("постороннему ответили: %v", f.texts())
	}
	events, err := st.Events(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "tg_stranger" {
		t.Fatalf("попытка не записана в журнал: %+v", events)
	}
	// Повторные попытки того же отправителя журнал не забивают.
	b.handle(ctx, m)
	events, _ = st.Events(ctx, 10)
	if len(events) != 1 {
		t.Fatalf("повторная попытка записана снова: %d", len(events))
	}
}

func TestCommands(t *testing.T) {
	f := newFakeAPI(t)
	b, _ := newTestBot(t, f, stubReporter{status: "статус сервера", online: "никого", server: "подробности"})
	ctx := context.Background()
	cases := map[string]string{
		"/status":         "статус сервера",
		"/online":         "никого",
		"/server de":      "подробности",
		"/status@awgdash": "статус сервера",
		"/help":           "Что умею",
		"/нетакой":        "не знаю такой команды",
	}
	for in, want := range cases {
		got, err := b.answer(ctx, in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if !strings.Contains(got, want) {
			t.Fatalf("%s → %q, ожидалось вхождение %q", in, got, want)
		}
	}
	// Обычный текст без команды остаётся без ответа.
	if got, _ := b.answer(ctx, "привет"); got != "" {
		t.Fatalf("на текст без команды ответили: %q", got)
	}
}

func TestEscapeInMessages(t *testing.T) {
	f := newFakeAPI(t)
	b, st := newTestBot(t, f, stubReporter{})
	ctx := context.Background()
	st.AddEvent(ctx, store.Event{Kind: "device_created", Severity: "crit", Message: `устройство «<b>hack</b> & co» создано`})
	if err := b.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if len(f.texts()) != 1 {
		t.Fatalf("сообщение не ушло: %v", f.texts())
	}
	if strings.Contains(f.texts()[0], "<b>hack") {
		t.Fatalf("разметка из имени не экранирована: %q", f.texts()[0])
	}
	if !strings.Contains(f.texts()[0], "&amp; co") {
		t.Fatalf("амперсанд не экранирован: %q", f.texts()[0])
	}
}
