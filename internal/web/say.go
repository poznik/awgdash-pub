package web

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/clientconf"
	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/store"
)

// Выводы словами (design.md «Панель говорит выводами», PLAN-UI §1.4). Считаются здесь, а не в
// шаблоне: разметка не должна решать, что значит отсутствие хендшейка.

// deviceSay — что происходит с устройством. ifaceUp — поднят ли его интерфейс, growth — прирост
// счётчиков за последние пять минут (для «застрял»), lastSeen — когда через устройство последний
// раз шёл трафик (ноль, если история не сохранилась).
func (s *Server) deviceSay(d store.Device, ifaceUp bool, growth uint64, lastSeen time.Time) (say, level string) {
	switch {
	case d.ServerRetired:
		return "Сервер выведен из парка — это устройство больше не подключится. Заведите новое на живом сервере", "crit"
	case !d.DeletedAt.IsZero():
		return "В корзине с " + s.fmtDate(d.DeletedAt) + " — адрес держится за устройством 30 дней", "crit"
	case d.Status == "disabled":
		return "Отключено в панели: пир снят с интерфейса, конфиг не работает", "crit"
	case d.Online():
		return "В туннеле, отвечало " + s.fmtAge(d.LastHandshake) + " назад", "ok"
	case !ifaceUp:
		return "Интерфейс не поднят — сейчас не работает ни у кого", "crit"
	case !d.OnInterface:
		return "Пира нет на интерфейсе: панель и сервер разошлись, помогает сверка", "crit"
	// Счётчики растут, а рукопожатия не было ни разу: клиент стучится и не может договориться.
	// На живом парке это выглядело как 148 байт каждые 15 секунд — попытки рукопожатия, и
	// подпись «застряло никогда» ничего человеку не объясняла.
	case growth > 0 && d.LastHandshake.IsZero():
		return "Устройство стучится, но туннель не встаёт: рукопожатия не было ни разу — не подходит конфиг (ключ, PSK или обфускация)", "warn"
	case growth > 0 && growth < hub.StuckGrowth:
		return "Застряло: счётчики растут, а рукопожатия нет — переподключите туннель", "warn"
	// Рукопожатие обнуляется вместе с интерфейсом: после его перезапуска пир выглядит как
	// новенький, хотя трафик через него шёл. История переживает сброс — по ней и видно разницу
	// между «конфиг не поставили» и «связь пропала», а заодно когда именно она пропала.
	case d.LastHandshake.IsZero() && !lastSeen.IsZero():
		return "Последний раз на связи " + s.fmtStamp(lastSeen) + " — рукопожатий с тех пор нет", "warn"
	case d.LastHandshake.IsZero() && d.RxTotal+d.TxTotal > 0:
		return "Связи нет с перезапуска интерфейса — раньше трафик через это устройство шёл", "warn"
	case d.LastHandshake.IsZero():
		return "Ни разу не подключалось — конфиг ещё не поставили на устройство", "warn"
	default:
		return fmt.Sprintf("Не в туннеле уже %s; пир на месте, сервер жив — значит, туннель выключен на самом устройстве",
			s.fmtAge(d.LastHandshake)), ""
	}
}

// userSay — строка под именем пользователя в его карточке.
func (s *Server) userSay(u store.User) string {
	switch {
	case !u.DeletedAt.IsZero():
		return "В корзине — восстановить можно 30 дней с удаления"
	case u.Disabled():
		return "Отключён вами: все устройства сняты с интерфейсов"
	case u.Expired():
		return "Срок доступа истёк " + s.fmtAge(u.ExpiresAt) + " назад — устройства сняты"
	case u.Devices == 0:
		return "Устройств пока нет — первое заводится кнопкой справа"
	case u.Online > 0:
		return fmt.Sprintf("%s из %d сейчас в туннеле", plural(u.Online, "устройство", "устройства", "устройств"), u.DevicesActive)
	case !u.LastHandshake.IsZero():
		return "Ни одного устройства в туннеле; последнее отвечало " + s.fmtAge(u.LastHandshake) + " назад"
	default:
		return "Ни одно устройство ещё не подключалось"
	}
}

// deviceShort — статус для карточки в списке: короткая подпись и уровень для точки.
// Развёрнутый вывод (deviceSay) живёт там, где разбираются с проблемой: страница устройства
// и экран выдачи.
func (s *Server) deviceShort(d store.Device, ifaceUp bool, growth uint64, lastSeen time.Time) (label, level string) {
	switch {
	case d.ServerRetired:
		return "сервер выведен", "crit"
	case !d.DeletedAt.IsZero():
		return "в корзине", "crit"
	case d.Status == "disabled":
		return "отключено", "crit"
	case d.Online():
		return "онлайн " + s.fmtAge(d.LastHandshake), "ok"
	case !ifaceUp:
		return "интерфейс не поднят", "crit"
	case !d.OnInterface:
		return "нет на интерфейсе", "crit"
	case growth > 0 && d.LastHandshake.IsZero():
		return "туннель не встаёт", "warn"
	case growth > 0 && growth < hub.StuckGrowth:
		return "застряло " + s.fmtAge(d.LastHandshake), "warn"
	case d.LastHandshake.IsZero() && !lastSeen.IsZero():
		return "последний раз " + s.fmtStamp(lastSeen), ""
	case d.LastHandshake.IsZero() && d.RxTotal+d.TxTotal > 0:
		return "нет связи", ""
	case d.LastHandshake.IsZero():
		return "ни разу не подключалось", ""
	default:
		return "офлайн " + s.fmtAge(d.LastHandshake), ""
	}
}

// ifaceSay — что происходит на интерфейсе, одной фразой.
func (s *Server) ifaceSay(det *interfaceDetail) string {
	if det.Status == store.StatusGone {
		return "Интерфейса больше нет на сервере: конфиг сняли, опрашивать нечего. Панель держит его записи, пока их не убрать"
	}
	if !det.UnitActive {
		return "Интерфейс не поднят — туннель не работает ни у кого. Поднимает systemd: awg-quick@" + det.Name
	}
	// «Прошло» — весь объём через интерфейс: и то, что клиенты скачали, и то, что отдали.
	// Раньше бралась только серверная половина rx, и цифра занижалась в разы.
	head := fmt.Sprintf("%s из %d в туннеле, за сутки прошло %s.",
		plural(det.Online, "пир", "пира", "пиров"), len(det.Peers), fmtBytes(det.Totals.DayRx+det.Totals.DayTx))
	if len(det.Peers) == 0 {
		head = "Пиров на интерфейсе нет."
	}
	switch {
	case det.LastVerifyOK != nil && !*det.LastVerifyOK:
		return head + " Обфускация в файле и в рантайме разошлась — клиенты могут не подключиться."
	case det.Mode != "own":
		return head + " Панель только наблюдает: пирами она не управляет."
	case det.Unassigned > 0:
		return head + fmt.Sprintf(" %s без владельца — панель не знает их приватных ключей.",
			plural(det.Unassigned, "пир", "пира", "пиров"))
	}
	return head + " Панель владеет пирами, расхождений нет."
}

// deviceLevel — цвет точки у устройства в списке; совпадает с уровнем фразы.
func (s *Server) deviceLevel(d store.Device, ifaceUp bool, growth uint64, lastSeen time.Time) string {
	_, level := s.deviceSay(d, ifaceUp, growth, lastSeen)
	return level
}

// sayMove — что получилось из переноса одного устройства (FR-3.9). Панель говорит вывод:
// переименование и поднятый лимит человек должен увидеть сразу, а не обнаружить потом.
func sayMove(res store.MoveResult, to string) string {
	if len(res.Moved) == 0 {
		return "переносить было нечего"
	}
	m := res.Moved[0]
	out := "«" + m.Name + "» теперь у «" + to + "»"
	if m.Renamed() {
		out += " · имя было занято, стало «" + m.Name + "»"
	}
	out += sayMoveExtras(res, to)
	return out
}

// sayMerge — итог объединения двух людей (FR-2.7).
func sayMerge(res hub.MergeResult) string {
	out := plural(len(res.Moved), "устройство", "устройства", "устройств") + " у «" + res.To + "»"
	if n := res.Renamed(); n > 0 {
		out += " · " + plural(n, "имя было занято и получило суффикс", "имени были заняты и получили суффикс", "имён были заняты и получили суффикс")
	}
	if res.InTrash > 0 {
		out += " · " + plural(res.InTrash, "устройство осталось", "устройства остались", "устройств осталось") + " в корзине у «" + res.From + "»"
	}
	out += sayMoveExtras(res.MoveResult, res.To)
	if res.Deleted {
		out += " · «" + res.From + "» удалён"
	}
	return out
}

// sayMoveExtras — общие для обоих случаев оговорки: поднятый лимит и сервер вне разрешённых.
func sayMoveExtras(res store.MoveResult, to string) string {
	out := ""
	if res.NewLimit > 0 {
		out += " · лимит устройств поднят до " + itoa(int64(res.NewLimit))
	}
	if len(res.Foreign) > 0 {
		out += " · " + plural(len(res.Foreign), "устройство стоит", "устройства стоят", "устройств стоят") +
			" на сервере вне списка разрешённых «" + to + "»: в портале он там новых не заведёт"
	}
	return out
}

// hintsOf — что подставится в конфиг, если поля «тонкостей» оставить пустыми. Форма создания
// устройства показывает эти значения плейсхолдерами: «как на интерфейсе» заставляло уходить на
// страницу интерфейса и сверять там, а часть значений (AllowedIPs по типу устройства) не видна
// вовсе. Пустое умолчание названо словами: строки в конфиге тогда не будет.
func hintsOf(c hub.IfaceChoice) ifaceHints {
	return hintsFrom(c.DNS, c.MTU, c.Keepalive, c.AllowedIPs, c.Subnet)
}

// hintsOfIface — то же для страницы устройства, где интерфейс уже известен целиком.
func hintsOfIface(i store.Interface) ifaceHints {
	return hintsFrom(i.DefaultDNS, i.MTU, i.DefaultKeepalive, i.DefaultAllowedIPs, i.Subnet)
}

func hintsFrom(dns string, mtu, keepalive int, allowedIPs, subnet string) ifaceHints {
	h := ifaceHints{
		DNS:             dns,
		MTU:             itoa(int64(mtu)),
		Keepalive:       itoa(int64(keepalive)),
		KeepaliveRouter: itoa(int64(clientconf.RouterKeepalive)),
		AllowedIPs:      allowedIPs,
	}
	if h.DNS == "" {
		h.DNS = "без строки DNS"
	}
	if mtu == 0 {
		h.MTU = "без строки MTU"
	}
	if keepalive == 0 {
		h.Keepalive = "без keepalive"
	}
	if h.AllowedIPs == "" {
		h.AllowedIPs = "0.0.0.0/0"
	}
	// Список роутера считается по подсети (FR-4.3), и полтора десятка префиксов в подсказку
	// не уместить: он назван словами, а подсеть туннеля показана — она в этом списке есть.
	h.AllowedIPsRouter = "интернет без локальных сетей"
	if list, err := clientconf.RouterAllowedIPs(subnet); err == nil {
		if p, err := netip.ParsePrefix(strings.TrimSpace(subnet)); err == nil {
			m := p.Masked().String()
			for _, v := range list {
				if v == m {
					h.AllowedIPsRouter += ", плюс " + m
					break
				}
			}
		}
	}
	return h
}

// firstHints — подсказки интерфейса, отмеченного в форме по умолчанию. Пустой парк даёт пустые
// подсказки: форма всё равно рендерится (модалка лежит на странице списка).
func firstHints(list []ifaceChoice) ifaceHints {
	if len(list) == 0 {
		return ifaceHints{}
	}
	return list[0].Hints
}
