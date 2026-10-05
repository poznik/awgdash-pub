// Package telegram — оповещатель администратора: клиент Bot API на net/http, рассылка событий
// с антифлудом и команды чтения (SPEC §6.8). Входящих портов не открывает: long polling.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// DefaultAPI — база Bot API. Отдельным полем, чтобы тесты подставляли httptest-сервер.
const DefaultAPI = "https://api.telegram.org"

// Client — минимум методов Bot API, которые нужны панели.
type Client struct {
	Token string
	API   string
	HTTP  *http.Client
}

// NewClient собирает клиента с таймаутами: long polling ждёт долго, поэтому таймаут запроса
// задаётся не здесь, а контекстом вызова.
func NewClient(token string) *Client {
	return &Client{Token: token, API: DefaultAPI, HTTP: &http.Client{Timeout: 90 * time.Second}}
}

// Error — ошибка Bot API с кодом: 401 значит «токен не тот», 409 — «включён вебхук»,
// 429 — «слишком часто»; по коду вызывающий решает, стоит ли повторять.
type Error struct {
	Code       int
	Message    string
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("telegram %d: %s (повторить через %s)", e.Code, e.Message, e.RetryAfter)
	}
	return fmt.Sprintf("telegram %d: %s", e.Code, e.Message)
}

type apiResponse struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   int             `json:"error_code"`
	Description string          `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

func (c *Client) call(ctx context.Context, method string, body any, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url(method), bytes.NewReader(buf))
	if err != nil {
		return c.hide(err)
	}
	req.Header.Set("Content-Type", "application/json")
	return c.do(req, out)
}

// hide убирает токен из текста ошибки. URL Bot API — это `…/bot<ТОКЕН>/<метод>`, а сетевые
// ошибки Go (*url.Error) несут URL в тексте: без маскирования полный токен бота утекал в
// journald на каждом обрыве связи с api.telegram.org (аудит, находка №10).
func (c *Client) hide(err error) error {
	if err == nil || c.Token == "" {
		return err
	}
	if msg := err.Error(); strings.Contains(msg, c.Token) {
		return fmt.Errorf("%s", strings.ReplaceAll(msg, c.Token, "bot***"))
	}
	return err
}

func (c *Client) do(req *http.Request, out any) error {
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return c.hide(err)
	}
	defer resp.Body.Close()
	// Ответы Bot API невелики; ограничение защищает от «ответа» постороннего сервера.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	var r apiResponse
	if err := json.Unmarshal(raw, &r); err != nil {
		return fmt.Errorf("telegram: ответ не разобран (%d): %s", resp.StatusCode, trim(string(raw), 200))
	}
	if !r.OK {
		return &Error{Code: r.ErrorCode, Message: r.Description, RetryAfter: time.Duration(r.Parameters.RetryAfter) * time.Second}
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(r.Result, out)
}

func (c *Client) url(method string) string {
	base := c.API
	if base == "" {
		base = DefaultAPI
	}
	return strings.TrimSuffix(base, "/") + "/bot" + c.Token + "/" + method
}

// User — то, что нужно от getMe: имя бота для diagnostics.
type User struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Name     string `json:"first_name"`
}

// GetMe проверяет токен (используется в awgdash doctor).
func (c *Client) GetMe(ctx context.Context) (User, error) {
	var u User
	err := c.call(ctx, "getMe", struct{}{}, &u)
	return u, err
}

// Message — то немногое, что нам нужно от входящего сообщения.
type Message struct {
	ID   int64 `json:"message_id"`
	From struct {
		ID       int64  `json:"id"`
		Username string `json:"username"`
		Name     string `json:"first_name"`
	} `json:"from"`
	Chat struct {
		ID   int64  `json:"id"`
		Type string `json:"type"`
	} `json:"chat"`
	Date int64  `json:"date"`
	Text string `json:"text"`
}

// Update — обновление long polling.
type Update struct {
	ID      int64    `json:"update_id"`
	Message *Message `json:"message"`
}

// GetUpdates забирает обновления, ожидая на сервере до timeout. Разрешены только сообщения:
// остальные типы бот не обрабатывает, и просить их у сервера незачем.
func (c *Client) GetUpdates(ctx context.Context, offset int64, timeout time.Duration) ([]Update, error) {
	body := map[string]any{"offset": offset, "timeout": int(timeout.Seconds()), "allowed_updates": []string{"message"}}
	var ups []Update
	err := c.call(ctx, "getUpdates", body, &ups)
	return ups, err
}

// DeleteWebhook снимает вебхук: если он включён, getUpdates отвечает 409 и бот молчит навсегда.
func (c *Client) DeleteWebhook(ctx context.Context) error {
	return c.call(ctx, "deleteWebhook", map[string]any{"drop_pending_updates": false}, nil)
}

// MaxMessage — лимит Bot API на длину сообщения; длинные тексты режутся по строкам.
const MaxMessage = 4096

// SendMessage отправляет текст в чат. Разметка — HTML: заголовки жирным, значения моноширинным;
// всё, что приходит из данных, экранируется функцией Esc.
func (c *Client) SendMessage(ctx context.Context, chatID int64, text string) error {
	for _, part := range Split(text, MaxMessage) {
		body := map[string]any{
			"chat_id":                  chatID,
			"text":                     part,
			"parse_mode":               "HTML",
			"disable_web_page_preview": true,
		}
		if err := c.call(ctx, "sendMessage", body, nil); err != nil {
			return err
		}
	}
	return nil
}

// SendDocument отправляет файл (бэкап в личку администратора, §6.9).
func (c *Client) SendDocument(ctx context.Context, chatID int64, filename string, data []byte, caption string) error {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("chat_id", strconv.FormatInt(chatID, 10))
	if caption != "" {
		_ = mw.WriteField("caption", caption)
	}
	part, err := mw.CreateFormFile("document", filename)
	if err != nil {
		return err
	}
	if _, err := part.Write(data); err != nil {
		return err
	}
	if err := mw.Close(); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("sendDocument"), &buf)
	if err != nil {
		return c.hide(err)
	}
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return c.do(req, nil)
}

// Split режет длинный текст на части по границам строк: обрезать сообщение молча — потерять данные.
func Split(text string, limit int) []string {
	if len(text) <= limit {
		return []string{text}
	}
	var out []string
	var cur strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if len(line) > limit { // одна строка длиннее лимита — режем как есть
			line = trim(line, limit-1)
		}
		if cur.Len()+len(line)+1 > limit {
			out = append(out, cur.String())
			cur.Reset()
		}
		if cur.Len() > 0 {
			cur.WriteByte('\n')
		}
		cur.WriteString(line)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// Esc экранирует текст для parse_mode=HTML: имена устройств и пользователей приходят от человека.
func Esc(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	// Режем по границе руны: обрывок UTF-8 Bot API не примет.
	for n > 0 && !isStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}

func isStart(b byte) bool { return b&0xC0 != 0x80 }
