package web

import (
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/store"
)

// funcs — форматирование для шаблонов. Всё, что видит человек, пишется по-русски здесь,
// а не в разметке: одно место на все страницы.
func (s *Server) funcs() template.FuncMap {
	return template.FuncMap{
		// bytes принимает любое целое: размеры приходят и uint64 (счётчики трафика), и int64
		// (размер файла копии). Шаблон падал на несовпадении типа — при живых копиях страница
		// настроек не открывалась вовсе.
		"bytes":     fmtBytesAny,
		"bps":       fmtBps,
		"age":       s.fmtAge,
		"when":      s.fmtWhen,
		"date":      s.fmtDate,
		"short":     shortKey,
		"adoptname": adoptName,
		"ua":        uaShort,
		"pct":       pct,
		"join":      strings.Join,
		"state":     func(t time.Time) string { l, _ := hub.PeerState(t, time.Now()); return l },
		"stateClass": func(t time.Time) string {
			_, c := hub.PeerState(t, time.Now())
			return c
		},
		"deviceState": deviceState,
		"deviceClass": deviceClass,
		"userState":   userState,
		"userClass":   userClass,
		"plural":      plural,
		"initial":     initial,
		"preset":      presetIcon,
		"action":      actionPhrase,
		"flag":        countryFlag,
		"deref":       func(b *bool) bool { return b != nil && *b },
		"allowedHas":  allowedHas,
		"add":         func(a, b int) int { return a + b },
		"add64":       func(a, b uint64) uint64 { return a + b },
		"sub":         func(a, b int) int { return a - b },
		"seq":         seq,
		"raw":         func(s string) template.HTML { return template.HTML(s) },
		// Для <style> нужен именно template.CSS: template.HTML в этом контексте отвергается,
		// и вместо стилей на странице оказывается маркер ZgotmplZ.
		"css": func(s string) template.CSS { return template.CSS(s) },
		"hpct": func(v, m uint64) string {
			if m == 0 {
				return "0%"
			}
			return fmt.Sprintf("%.0f%%", float64(v)/float64(m)*100)
		},
	}
}

// initial — первая буква имени для кружка в шапке.
func initial(name string) string {
	for _, r := range strings.TrimSpace(name) {
		return strings.ToUpper(string(r))
	}
	return "?"
}

// presetIcon — какой значок у устройства: id символа из спрайта раскладки.
func presetIcon(preset string) string {
	switch preset {
	case store.PresetRouter:
		return "router"
	case store.PresetCustom:
		return "gear"
	default:
		return "phone"
	}
}

// actionPhrase переводит код аудита в предложение: журнал читают глазами, а не грепом.
func actionPhrase(action string) string {
	if s, ok := actionWords[action]; ok {
		return s
	}
	return action
}

var actionWords = map[string]string{
	"user.create":       "пользователь заведён",
	"user.update":       "правки в карточке",
	"user.status":       "включение или отключение",
	"user.delete":       "удалён в корзину",
	"user.restore":      "восстановлен из корзины",
	"user.link_reissue": "ссылка портала перевыпущена",
	"user.merge":        "объединён с другим пользователем",
	"device.create":     "устройство добавлено",
	"device.update":     "устройство изменено",
	"device.status":     "устройство включено или отключено",
	"device.delete":     "устройство удалено",
	"device.restore":    "устройство восстановлено",
	"device.rotate":     "ключи устройства перевыпущены",
	"device.move":       "устройство передано другому",
	"device.issue":      "конфиг выдан",
	"iface.mode":        "режим интерфейса изменён",
	"iface.reconcile":   "интерфейс приведён к панели",
	"peer.adopt":        "пир привязан к пользователю",
	"admin.login":       "вход в панель",
	"panel.brand":       "панель переименована",
	"trash.purge":       "корзина очищена",
	"server.retire":     "сервер выведен из парка",
	"server.return":     "сервер возвращён в парк",
	"server.delete":     "сервер удалён из панели",
}

// deviceState — подпись состояния устройства для списка и карточки.
func deviceState(d store.Device) string {
	switch {
	case !d.DeletedAt.IsZero():
		return "в корзине"
	case d.Status == "disabled":
		return "отключено"
	case d.Online():
		return "онлайн"
	case !d.OnInterface:
		return "нет на интерфейсе"
	case d.LastHandshake.IsZero() && d.RxTotal+d.TxTotal > 0:
		return "нет связи"
	case d.LastHandshake.IsZero():
		return "ни разу не подключалось"
	default:
		return "офлайн"
	}
}

func deviceClass(d store.Device) string {
	switch {
	case !d.DeletedAt.IsZero() || d.Status == "disabled":
		return "dot--crit"
	case d.Online():
		return "dot--ok"
	case !d.OnInterface:
		return "dot--warn"
	default:
		return "dot--muted"
	}
}

func userState(u store.User) string {
	switch {
	case !u.DeletedAt.IsZero():
		return "в корзине"
	case u.Expired():
		return "срок истёк"
	case u.Disabled():
		return "отключён"
	case u.Online > 0:
		return fmt.Sprintf("онлайн %d из %d", u.Online, u.DevicesActive)
	case u.Devices == 0:
		return "нет устройств"
	default:
		return "офлайн"
	}
}

func userClass(u store.User) string {
	switch {
	case !u.DeletedAt.IsZero() || u.Disabled():
		return "dot--crit"
	case u.Online > 0:
		return "dot--ok"
	case u.Devices == 0:
		return "dot--muted"
	default:
		return "dot--muted"
	}
}

// plural — «3 устройства»: формы для 1, 2–4 и 5+.
// countryFlag рисует флаг страны картинкой из спрайта: эмодзи-флаги Windows не отображает —
// вместо 🇩🇪 браузер показывает буквы «DE», и панель выглядела набором кодов. Для страны без
// рисунка остаётся тот же код, но набранный как метка.
func countryFlag(code string) template.HTML {
	code = strings.ToLower(strings.TrimSpace(code))
	if len(code) != 2 {
		return ""
	}
	switch code {
	case "de", "fi", "ru", "kz", "nl", "us":
		return template.HTML(`<svg class="flag" aria-hidden="true"><use href="#flag-` + code + `"/></svg>`)
	}
	return template.HTML(`<span class="flag flag--code">` + template.HTMLEscapeString(strings.ToUpper(code)) + `</span>`)
}

func plural(n int, one, few, many string) string {
	mod100, mod10 := n%100, n%10
	switch {
	case mod100 >= 11 && mod100 <= 14:
		return fmt.Sprintf("%d %s", n, many)
	case mod10 == 1:
		return fmt.Sprintf("%d %s", n, one)
	case mod10 >= 2 && mod10 <= 4:
		return fmt.Sprintf("%d %s", n, few)
	default:
		return fmt.Sprintf("%d %s", n, many)
	}
}

func seq(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

// fmtBytesAny — обёртка для шаблонов: приводит любое целое к uint64 и печатает размер.
func fmtBytesAny(v any) string {
	switch n := v.(type) {
	case uint64:
		return fmtBytes(n)
	case int64:
		if n < 0 {
			return "0"
		}
		return fmtBytes(uint64(n))
	case int:
		if n < 0 {
			return "0"
		}
		return fmtBytes(uint64(n))
	case float64:
		if n < 0 {
			return "0"
		}
		return fmtBytes(uint64(n))
	default:
		return fmt.Sprintf("%v", v)
	}
}

func fmtBytes(b uint64) string {
	switch {
	case b == 0:
		return "0"
	case b < 1_000_000:
		return fmt.Sprintf("%.0f КБ", float64(b)/1e3)
	case b < 1_000_000_000:
		return fmt.Sprintf("%.1f МБ", float64(b)/1e6)
	case b < 1_000_000_000_000:
		return fmt.Sprintf("%.2f ГБ", float64(b)/1e9)
	default:
		return fmt.Sprintf("%.2f ТБ", float64(b)/1e12)
	}
}

func fmtBps(b uint64) string {
	switch {
	case b < 1_000:
		return "0"
	case b < 1_000_000:
		return fmt.Sprintf("%.0f КБ/с", float64(b)/1e3)
	default:
		return fmt.Sprintf("%.1f МБ/с", float64(b)/1e6)
	}
}

func (s *Server) fmtAge(t time.Time) string {
	if t.IsZero() {
		return "никогда"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d с", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d ч", int(d.Hours()))
	default:
		return fmt.Sprintf("%d дн", int(d.Hours()/24))
	}
}

func (s *Server) fmtWhen(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.In(s.TZ).Format("02.01 15:04:05")
}

// fmtStamp — «25.08.2026 в 19:38»: полная дата с временем, когда важно назвать момент, а не
// «сколько прошло».
func (s *Server) fmtStamp(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.In(s.TZ).Format("02.01.2006 в 15:04")
}

func (s *Server) fmtDate(t time.Time) string {
	if t.IsZero() {
		return "—"
	}
	return t.In(s.TZ).Format("02.01.2006")
}

func shortKey(k string) string {
	if len(k) <= 12 {
		return k
	}
	return k[:8] + "…" + k[len(k)-4:]
}

// adoptName — имя устройства для ничьего пира, когда его не задали руками (FR-1.6). Из ключа
// берутся только буквы и цифры: base64 приносит «+» и «/», а shortKey — ещё и многоточие, и на
// таком имени привязка отбивалась валидацией FR-3.8, то есть кнопка не работала вовсе.
func adoptName(pub string) string {
	var b strings.Builder
	n := 0
	for _, r := range pub {
		if n == 8 {
			break
		}
		if ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z') || ('0' <= r && r <= '9') {
			b.WriteRune(r)
			n++
		}
	}
	if n == 0 {
		return "пир без имени"
	}
	return "пир " + b.String()
}

func pct(used, total uint64) string {
	if total == 0 {
		return "—"
	}
	return fmt.Sprintf("%.0f %%", float64(used)/float64(total)*100)
}

// uaShort сокращает User-Agent до «браузер · система»: полная строка растягивала таблицу
// сессий до горизонтальной прокрутки, а читать её целиком всё равно незачем (есть title).
func uaShort(ua string) string {
	if ua == "" {
		return "—"
	}
	browsers := []struct{ marker, name string }{
		{"Edg/", "Edge"}, {"YaBrowser/", "Яндекс"}, {"OPR/", "Opera"}, {"Chrome/", "Chrome"},
		{"Firefox/", "Firefox"}, {"Version/", "Safari"},
	}
	name := "браузер"
	for _, b := range browsers {
		if i := strings.Index(ua, b.marker); i >= 0 {
			ver := ua[i+len(b.marker):]
			if j := strings.IndexAny(ver, ". "); j > 0 {
				ver = ver[:j]
			}
			name = b.name + " " + ver
			break
		}
	}
	systems := []struct{ marker, name string }{
		{"Windows NT 10.0", "Windows"}, {"Windows", "Windows"}, {"iPhone", "iPhone"}, {"iPad", "iPad"},
		{"Android", "Android"}, {"Mac OS X", "macOS"}, {"Linux", "Linux"},
	}
	for _, s := range systems {
		if strings.Contains(ua, s.marker) {
			return name + " · " + s.name
		}
	}
	return name
}

// allowedHas — отмечен ли интерфейс в списке разрешённых пользователю.
func allowedHas(allowed []int64, id int64) bool {
	for _, v := range allowed {
		if v == id {
			return true
		}
	}
	return false
}
