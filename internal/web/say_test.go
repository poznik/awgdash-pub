package web

import (
	"strings"
	"testing"
	"time"

	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/store"
)

// Таблица выводов из PLAN-UI §1.4: на каждый случай — своя фраза. Панель отвечает на вопрос
// «почему не работает», а не выкладывает цифры.
func TestDeviceSay(t *testing.T) {
	s := &Server{TZ: time.UTC}
	now := time.Now()
	on := store.Device{Status: "active", OnInterface: true, LastHandshake: now.Add(-25 * time.Second)}

	cases := []struct {
		name     string
		dev      store.Device
		ifaceUp  bool
		growth   uint64
		lastSeen time.Time
		want     string
		level    string
	}{
		{"в туннеле", on, true, 0, time.Time{}, "В туннеле", "ok"},
		{"выключено в панели", store.Device{Status: "disabled", OnInterface: false}, true, 0, time.Time{}, "Отключено в панели", "crit"},
		{"интерфейс не поднят", store.Device{Status: "active", OnInterface: true, LastHandshake: now.Add(-time.Hour)}, false, 0, time.Time{}, "Интерфейс не поднят", "crit"},
		{"пира нет на интерфейсе", store.Device{Status: "active", LastHandshake: now.Add(-time.Hour)}, true, 0, time.Time{}, "Пира нет на интерфейсе", "crit"},
		{"застряло", store.Device{Status: "active", OnInterface: true, LastHandshake: now.Add(-time.Hour)}, true, hub.StuckGrowth - 1, time.Time{}, "Застряло", "warn"},
		{"ни разу", store.Device{Status: "active", OnInterface: true}, true, 0, time.Time{}, "Ни разу не подключалось", "warn"},
		{"выключено на устройстве", store.Device{Status: "active", OnInterface: true, LastHandshake: now.Add(-4 * time.Hour)}, true, 0, time.Time{}, "туннель выключен на самом устройстве", ""},
		{"в корзине", store.Device{Status: "active", DeletedAt: now.Add(-24 * time.Hour)}, true, 0, time.Time{}, "В корзине", "crit"},
	}
	for _, c := range cases {
		say, level := s.deviceSay(c.dev, c.ifaceUp, c.growth, c.lastSeen)
		if !strings.Contains(say, c.want) {
			t.Errorf("%s: сказано %q, ожидалось про %q", c.name, say, c.want)
		}
		if level != c.level {
			t.Errorf("%s: уровень %q, ожидался %q", c.name, level, c.level)
		}
	}
}

func TestUserSay(t *testing.T) {
	s := &Server{TZ: time.UTC}
	now := time.Now()
	cases := []struct {
		name string
		u    store.User
		want string
	}{
		{"онлайн", store.User{Status: "active", Devices: 3, DevicesActive: 3, Online: 2}, "2 устройства из 3 сейчас в туннеле"},
		{"без устройств", store.User{Status: "active"}, "Устройств пока нет"},
		{"отключён", store.User{Status: "disabled", Devices: 2}, "Отключён вами"},
		{"срок истёк", store.User{Status: "active", Devices: 1, ExpiresAt: now.Add(-48 * time.Hour)}, "Срок доступа истёк"},
		{"в корзине", store.User{Status: "active", Devices: 1, DeletedAt: now}, "В корзине"},
	}
	for _, c := range cases {
		if got := s.userSay(c.u); !strings.Contains(got, c.want) {
			t.Errorf("%s: сказано %q, ожидалось про %q", c.name, got, c.want)
		}
	}
}

// Карточка устройства обходится точкой и короткой подписью: разбор «почему не работает»
// живёт на странице устройства, а не в списке.
func TestDeviceShort(t *testing.T) {
	s := &Server{TZ: time.UTC}
	now := time.Now()
	cases := []struct {
		name     string
		dev      store.Device
		ifaceUp  bool
		growth   uint64
		lastSeen time.Time
		want     string
		level    string
	}{
		{"в туннеле", store.Device{Status: "active", OnInterface: true, LastHandshake: now.Add(-25 * time.Second)}, true, 0, time.Time{}, "онлайн ", "ok"},
		{"офлайн", store.Device{Status: "active", OnInterface: true, LastHandshake: now.Add(-4 * time.Hour)}, true, 0, time.Time{}, "офлайн ", ""},
		{"отключено", store.Device{Status: "disabled"}, true, 0, time.Time{}, "отключено", "crit"},
		{"интерфейс лежит", store.Device{Status: "active", OnInterface: true, LastHandshake: now.Add(-time.Hour)}, false, 0, time.Time{}, "интерфейс не поднят", "crit"},
		{"ни разу", store.Device{Status: "active", OnInterface: true}, true, 0, time.Time{}, "ни разу не подключалось", ""},
	}
	for _, c := range cases {
		label, level := s.deviceShort(c.dev, c.ifaceUp, c.growth, c.lastSeen)
		if !strings.HasPrefix(label, c.want) {
			t.Errorf("%s: подпись %q, ожидалась начинающаяся с %q", c.name, label, c.want)
		}
		if level != c.level {
			t.Errorf("%s: уровень %q, ожидался %q", c.name, level, c.level)
		}
	}
}

// Рукопожатие обнуляется вместе с интерфейсом, а накопленные итоги — нет. Пир без хендшейка,
// но с трафиком в истории — это потерянная связь, а не устройство, которому не поставили конфиг:
// на живой панели такие показывались как «ни разу не подключалось» при 35 МБ за сутки.
func TestSayTellsLostLinkFromNeverConnected(t *testing.T) {
	s := &Server{TZ: time.UTC}
	fresh := store.Device{Status: "active", OnInterface: true}
	say, _ := s.deviceSay(fresh, true, 0, time.Time{})
	if !strings.Contains(say, "Ни разу не подключалось") {
		t.Fatalf("устройство без трафика: %q", say)
	}
	if got := deviceState(fresh); got != "ни разу не подключалось" {
		t.Fatalf("подпись без трафика: %q", got)
	}

	worked := store.Device{Status: "active", OnInterface: true, RxTotal: 35_200_000, TxTotal: 159_500_000}
	say, level := s.deviceSay(worked, true, 0, time.Time{})
	if strings.Contains(say, "Ни разу не подключалось") {
		t.Fatalf("устройство с трафиком названо не подключавшимся: %q", say)
	}
	if !strings.Contains(say, "перезапуска интерфейса") || level != "warn" {
		t.Fatalf("фраза о потерянной связи: %q (%s)", say, level)
	}
	if got := deviceState(worked); got != "нет связи" {
		t.Fatalf("подпись с трафиком: %q", got)
	}

	// Клиент стучится, но рукопожатия не было ни разу: «застряло никогда» ничего не объясняло.
	knocking := store.Device{Status: "active", OnInterface: true, RxTotal: 172_272, TxTotal: 128_040}
	say, level = s.deviceSay(knocking, true, 258, time.Time{})
	if !strings.Contains(say, "туннель не встаёт") || level != "warn" {
		t.Fatalf("стучащееся устройство: %q (%s)", say, level)
	}
	if label, _ := s.deviceShort(knocking, true, 258, time.Time{}); strings.Contains(label, "никогда") {
		t.Fatalf("короткая подпись снова про «никогда»: %q", label)
	}

	// Когда история сохранила момент последнего трафика, панель называет его: «когда именно
	// пропало» человеку нужнее, чем «пропало после перезапуска».
	at := time.Date(2026, 8, 25, 19, 38, 0, 0, time.UTC)
	say, level = s.deviceSay(worked, true, 0, at)
	if !strings.Contains(say, "25.08.2026 в 19:38") || level != "warn" {
		t.Fatalf("фраза с датой последней связи: %q (%s)", say, level)
	}
	if label, _ := s.deviceShort(worked, true, 0, at); !strings.Contains(label, "25.08.2026 в 19:38") {
		t.Fatalf("короткая подпись с датой: %q", label)
	}
}
