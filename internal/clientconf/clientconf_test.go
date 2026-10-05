package clientconf

import (
	"strings"
	"testing"

	"github.com/poznik/awgdash-pub/internal/store"
)

// testIface — интерфейс по образцу awg-old: 12 параметров обфускации, из них I2..I5 не заданы.
func testIface() store.Interface {
	return store.Interface{
		Name:              "awg-old",
		Subnet:            "10.20.0.0/16",
		ServerAddress:     "10.20.0.1/16",
		ListenPort:        443,
		MTU:               1280,
		ServerPublicKey:   "SERVERPUBKEYSERVERPUBKEYSERVERPUBKEYSERVERP=",
		DefaultDNS:        "1.1.1.1, 8.8.8.8",
		DefaultKeepalive:  21,
		DefaultAllowedIPs: "0.0.0.0/0",
		PSKEnabled:        true,
		Endpoints: []store.Endpoint{
			{Label: "основной", Host: "vpn.example.com", Port: 443, Primary: true},
			{Label: "запасной порт", Host: "vpn.example.com", Port: 8443},
		},
		Obfuscation: map[string]string{
			"Jc": "6", "Jmin": "50", "Jmax": "1000",
			"S1": "77", "S2": "99", "S3": "0", "S4": "0",
			"H1": "1122334455", "H2": "2233445566", "H3": "3344556677", "H4": "4455667788",
			"I1": "<b 0xf1a2b3c4>",
			// I2..I5 в файле сервера отсутствуют; «0» тоже не должен попадать в конфиг.
			"I2": "0", "I3": "", "I4": "(null)", "I5": "0",
		},
	}
}

func testDevice() store.Device {
	return store.Device{
		Name:         "Телефон",
		Preset:       store.PresetPhone,
		PrivateKey:   "CLIENTPRIVATEKEYCLIENTPRIVATEKEYCLIENTPRIV=",
		PublicKey:    "CLIENTPUBLICKEYCLIENTPUBLICKEYCLIENTPUBLICK=",
		PresharedKey: "PRESHAREDKEYPRESHAREDKEYPRESHAREDKEYPRESHA=",
		Address:      "10.20.0.7",
		Status:       "active",
	}
}

const goldenPhone = `[Interface]
PrivateKey = CLIENTPRIVATEKEYCLIENTPRIVATEKEYCLIENTPRIV=
Address = 10.20.0.7/32
DNS = 1.1.1.1, 8.8.8.8
MTU = 1280
Jc = 6
Jmin = 50
Jmax = 1000
S1 = 77
S2 = 99
S3 = 0
S4 = 0
H1 = 1122334455
H2 = 2233445566
H3 = 3344556677
H4 = 4455667788
I1 = <b 0xf1a2b3c4>

[Peer]
PublicKey = SERVERPUBKEYSERVERPUBKEYSERVERPUBKEYSERVERP=
PresharedKey = PRESHAREDKEYPRESHAREDKEYPRESHAREDKEYPRESHA=
AllowedIPs = 0.0.0.0/0
Endpoint = vpn.example.com:443
PersistentKeepalive = 21
`

func TestBuildPhoneGolden(t *testing.T) {
	iface, d := testIface(), testDevice()
	ep, err := EndpointByLabel(iface, "")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Build(iface, d, ep)
	if err != nil {
		t.Fatal(err)
	}
	if got != goldenPhone {
		t.Fatalf("конфиг разошёлся с эталоном:\n--- получено ---\n%s\n--- ожидалось ---\n%s", got, goldenPhone)
	}
	// FR-4.2: незаданные I-пакеты не выводятся ни в каком виде.
	for _, k := range []string{"I2", "I3", "I4", "I5"} {
		if strings.Contains(got, k+" =") {
			t.Fatalf("в конфиге оказался %s:\n%s", k, got)
		}
	}
}

func TestBuildAlternateEndpoint(t *testing.T) {
	iface, d := testIface(), testDevice()
	ep, err := EndpointByLabel(iface, "запасной порт")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Build(iface, d, ep)
	if err != nil {
		t.Fatal(err)
	}
	// Варианты отличаются ровно одной строкой (FR-4.7).
	want := strings.Replace(goldenPhone, "Endpoint = vpn.example.com:443", "Endpoint = vpn.example.com:8443", 1)
	if got != want {
		t.Fatalf("вариант endpoint изменил не только Endpoint:\n%s", got)
	}
	if _, err := EndpointByLabel(iface, "нет такого"); err == nil {
		t.Fatal("принят несуществующий вариант endpoint")
	}
}

func TestBuildRouterPreset(t *testing.T) {
	iface, d := testIface(), testDevice()
	d.Preset = store.PresetRouter
	d.Name = "Keenetic"
	ep, _ := EndpointByLabel(iface, "")
	got, err := Build(iface, d, ep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "PersistentKeepalive = 25") {
		t.Fatalf("router: keepalive должен быть 25:\n%s", got)
	}
	line := ""
	for _, l := range strings.Split(got, "\n") {
		if strings.HasPrefix(l, "AllowedIPs = ") {
			line = strings.TrimPrefix(l, "AllowedIPs = ")
		}
	}
	if line == "" {
		t.Fatal("нет строки AllowedIPs")
	}
	for _, bad := range []string{"0.0.0.0/0,", "192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"} {
		if strings.Contains(line, bad) {
			t.Fatalf("router: в AllowedIPs осталось %s: %s", bad, line)
		}
	}
	if !strings.Contains(line, "10.20.0.0/16") {
		t.Fatalf("router: подсеть VPN должна остаться в туннеле: %s", line)
	}
}

func TestRouterAllowedIPsExact(t *testing.T) {
	got, err := RouterAllowedIPs("10.20.0.0/16")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"0.0.0.0/5", "8.0.0.0/7", "10.20.0.0/16", "11.0.0.0/8", "12.0.0.0/6", "16.0.0.0/4", "32.0.0.0/3",
		"64.0.0.0/2", "128.0.0.0/3", "160.0.0.0/5", "168.0.0.0/6", "172.0.0.0/12", "172.32.0.0/11",
		"172.64.0.0/10", "172.128.0.0/9", "173.0.0.0/8", "174.0.0.0/7", "176.0.0.0/4", "192.0.0.0/9",
		"192.128.0.0/11", "192.160.0.0/13", "192.169.0.0/16", "192.170.0.0/15", "192.172.0.0/14",
		"192.176.0.0/12", "192.192.0.0/10", "193.0.0.0/8", "194.0.0.0/7", "196.0.0.0/6", "200.0.0.0/5",
		"208.0.0.0/4",
	}
	if len(got) != len(want) {
		t.Fatalf("префиксов %d, ожидалось %d:\n%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("префикс %d = %s, ожидался %s\nвесь список: %v", i, got[i], want[i], got)
		}
	}
	// Без подсети VPN список короче ровно на неё.
	plain, err := RouterAllowedIPs("")
	if err != nil {
		t.Fatal(err)
	}
	if len(plain) != len(want)-1 {
		t.Fatalf("без подсети: %d префиксов, ожидалось %d", len(plain), len(want)-1)
	}
	if _, err := RouterAllowedIPs("не подсеть"); err == nil {
		t.Fatal("принята некорректная подсеть")
	}
}

func TestOverrides(t *testing.T) {
	iface, d := testIface(), testDevice()
	d.Overrides = store.Overrides{AllowedIPs: "10.20.0.0/16, 1.1.1.1/32", DNS: "9.9.9.9", MTU: 1420, Keepalive: 15}
	ep, _ := EndpointByLabel(iface, "")
	got, err := Build(iface, d, ep)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"DNS = 9.9.9.9", "MTU = 1420", "AllowedIPs = 10.20.0.0/16, 1.1.1.1/32", "PersistentKeepalive = 15"} {
		if !strings.Contains(got, want) {
			t.Fatalf("нет строки %q:\n%s", want, got)
		}
	}
	// Переопределения перекрывают и пресет router.
	d.Preset = store.PresetRouter
	got, _ = Build(iface, d, ep)
	if !strings.Contains(got, "AllowedIPs = 10.20.0.0/16, 1.1.1.1/32") || !strings.Contains(got, "PersistentKeepalive = 15") {
		t.Fatalf("переопределения не победили пресет:\n%s", got)
	}
}

func TestBuildWithoutPSKAndDNS(t *testing.T) {
	iface, d := testIface(), testDevice()
	iface.DefaultDNS = ""
	iface.DefaultKeepalive = 0
	d.PresharedKey = ""
	ep, _ := EndpointByLabel(iface, "")
	got, err := Build(iface, d, ep)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"DNS =", "PresharedKey =", "PersistentKeepalive ="} {
		if strings.Contains(got, bad) {
			t.Fatalf("пустое поле попало в конфиг (%s):\n%s", bad, got)
		}
	}
}

func TestBuildErrors(t *testing.T) {
	iface, d := testIface(), testDevice()
	ep, _ := EndpointByLabel(iface, "")

	noKey := d
	noKey.PrivateKey = ""
	if _, err := Build(iface, noKey, ep); err == nil {
		t.Fatal("конфиг собран без приватного ключа")
	}
	noServer := iface
	noServer.ServerPublicKey = ""
	if _, err := Build(noServer, d, ep); err == nil {
		t.Fatal("конфиг собран без ключа сервера")
	}
	if _, err := Build(iface, d, store.Endpoint{}); err == nil {
		t.Fatal("конфиг собран без endpoint")
	}
	custom := d
	custom.Preset = store.PresetCustom
	bare := iface
	bare.DefaultAllowedIPs = ""
	if _, err := Build(bare, custom, ep); err == nil {
		t.Fatal("пресет custom без AllowedIPs должен быть ошибкой")
	}
}

func TestFileName(t *testing.T) {
	cases := map[[2]string]string{
		{"Анна", "Телефон"}:           "Анна-Телефон.conf",
		{"Анна Петрова", "iPhone 15"}: "Анна-Петрова-iPhone-15.conf",
		{"a/b", "c:d"}:                "a-b-cd.conf",
		{"", ""}:                      "awgdash.conf",
	}
	for in, want := range cases {
		if got := FileName(in[0], in[1]); got != want {
			t.Fatalf("FileName(%q, %q) = %q, ожидалось %q", in[0], in[1], got, want)
		}
	}
}

// Чем пресеты отличаются на самом деле и во что это обходится по длине: длина важна для QR
// (FR-4.4), поэтому цифры держим под тестом, а не в голове.
func TestPresetDifference(t *testing.T) {
	iface := testIface()
	ep, _ := EndpointByLabel(iface, "")

	phone, router := testDevice(), testDevice()
	router.Preset = store.PresetRouter

	confPhone, err := Build(iface, phone, ep)
	if err != nil {
		t.Fatal(err)
	}
	confRouter, err := Build(iface, router, ep)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("телефон: %d символов, роутер: %d символов", len(confPhone), len(confRouter))

	// Отличаются ровно две строки: AllowedIPs и PersistentKeepalive.
	diff := 0
	linesA, linesB := strings.Split(confPhone, "\n"), strings.Split(confRouter, "\n")
	if len(linesA) != len(linesB) {
		t.Fatalf("разное число строк: %d и %d", len(linesA), len(linesB))
	}
	for i := range linesA {
		if linesA[i] != linesB[i] {
			diff++
			t.Logf("  строка %d:\n    телефон: %.60s\n    роутер:  %.60s", i+1, linesA[i], linesB[i])
		}
	}
	if diff != 2 {
		t.Fatalf("пресеты отличаются в %d строках, ожидалось 2 (AllowedIPs и keepalive)", diff)
	}
}
