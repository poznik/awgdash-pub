// Package awgtest — модель `awg` и `systemctl` для тестов: `set` меняет состояние, `show dump` его печатает.
// Пакет не импортируется боевым кодом и в бинарник не попадает.
package awgtest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Ключи и PSK для тестов: 44 символа, как настоящие.
const (
	KeyA = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	KeyB = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
	KeyC = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC="
	PSK  = "cHNrLXByZXNoYXJlZC1rZXktMzItYnl0ZXMtbGVuISE="
)

// ConfBody — конфиг по образцу боевого: комментарий, PostUp и порядок ключей обязаны пережить запись.
const ConfBody = `[Interface]
Address = 10.20.0.1/16
MTU = 1280
PostUp = iptables -t nat -A POSTROUTING -s 10.20.0.0/16 -o eth0 -j MASQUERADE
# комментарий, который обязан сохраниться
ListenPort = 443
PrivateKey = cHJpdmF0ZS1rZXktbmUtbG9naXJvdmF0eS1uaWtvZ2RhPT0=
Jc = 6
Jmin = 20
Jmax = 90
S1 = 40
S2 = 30
S3 = 12
S4 = 24
H1 = 100000001-100000999
H2 = 200000001-200000999
H3 = 300000001-300000999
H4 = 400000001-400000999
I1 = <b 0xc70000000108><r 8><b 0x00004100><r 4>
ContentPaddingAddition = 0

[Peer]
PublicKey = ` + KeyA + `
AllowedIPs = 10.20.0.2/32

[Peer]
PublicKey = ` + KeyB + `
PresharedKey = ` + PSK + `
AllowedIPs = 10.20.0.3/32
`

// ServerPublicKey — публичный ключ интерфейса в выдуманном рантайме.
const ServerPublicKey = "SERVERPUB="

// Peer — пир в модели рантайма.
type Peer struct {
	HasPSK  bool
	Allowed string
	// Handshake — время последнего рукопожатия (unix). Ноль значит «не подключался»,
	// как и в настоящем `awg show dump`.
	Handshake int64
}

// Call — записанный вызов внешней команды.
type Call struct {
	Args  []string
	Stdin string
}

// Fake реализует awg.Runner.
type Fake struct {
	Peers map[string]Peer
	// Foreign — «активен чужой менеджер пиров» для systemctl is-active.
	Foreign bool
	// Containers — состояние контейнеров для `docker inspect`: чужая панель может жить и так.
	// Отсутствующее имя моделирует «контейнера нет вовсе» — docker выходит с ошибкой.
	Containers map[string]bool
	// SetErr — ошибка, которую возвращает любой `awg set` (проверка отката).
	SetErr error
	// ObfRuntime подменяет параметры обфускации рантайма (сценарий дрейфа).
	ObfRuntime map[string]string
	Calls      []Call
}

// New — фейк с двумя пирами, как в ConfBody.
func New() *Fake {
	return &Fake{Peers: map[string]Peer{
		KeyA: {Allowed: "10.20.0.2/32"},
		KeyB: {HasPSK: true, Allowed: "10.20.0.3/32"},
	}}
}

// WriteConf кладёт ConfBody в каталог и возвращает путь к файлу.
func WriteConf(dir, iface string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, iface+".conf")
	return path, os.WriteFile(path, []byte(ConfBody), 0o600)
}

// Run исполняет команду по модели.
func (f *Fake) Run(_ context.Context, stdin []byte, name string, args ...string) ([]byte, error) {
	f.Calls = append(f.Calls, Call{Args: append([]string{name}, args...), Stdin: string(stdin)})
	switch {
	case name == "systemctl" && len(args) >= 1 && args[0] == "is-active":
		if f.Foreign {
			return []byte("active\n"), nil
		}
		return []byte("inactive\n"), nil
	case name == "docker" && len(args) >= 2 && args[0] == "inspect":
		container := args[len(args)-1]
		running, ok := f.Containers[container]
		if !ok {
			return nil, fmt.Errorf("Error: No such object: %s", container)
		}
		if running {
			return []byte("true\n"), nil
		}
		return []byte("false\n"), nil
	case len(args) >= 1 && args[0] == "--version":
		return []byte("amneziawg-tools v3.0.20260805 - https://amnezia.org\n"), nil
	case len(args) >= 3 && args[0] == "show" && args[2] == "dump":
		return []byte(f.Dump()), nil
	case len(args) >= 2 && args[0] == "show" && args[1] == "interfaces":
		return []byte("awg-t0\n"), nil
	case len(args) >= 1 && args[0] == "set":
		if f.SetErr != nil {
			return nil, f.SetErr
		}
		return nil, f.set(args, string(stdin))
	}
	return nil, fmt.Errorf("неожиданная команда %s %v", name, args)
}

// set моделирует `awg set <iface> peer <pub> [remove] [preshared-key <файл>] [allowed-ips …]`.
func (f *Fake) set(args []string, stdin string) error {
	if len(args) < 4 || args[2] != "peer" {
		return fmt.Errorf("не разобрана команда set: %v", args)
	}
	pub := args[3]
	p := f.Peers[pub]
	for i := 4; i < len(args); i++ {
		switch args[i] {
		case "remove":
			// Настоящий awg снимает несуществующий пир молча (проверено на живом сервере:
			// exit 0, прочие пиры на месте). Панель на это опирается: удаление уже отключённого
			// устройства снимает пир второй раз, и ошибкой это быть не должно.
			delete(f.Peers, pub)
			return nil
		case "preshared-key":
			if args[i+1] != "/dev/stdin" {
				return fmt.Errorf("PSK обязан идти через stdin, а не через %s", args[i+1])
			}
			p.HasPSK = strings.TrimSpace(stdin) != ""
			i++
		case "allowed-ips":
			p.Allowed = args[i+1]
			i++
		}
	}
	f.Peers[pub] = p
	return nil
}

// Dump печатает рантайм в формате `awg show <if> dump`.
func (f *Fake) Dump() string {
	obf := []string{"6", "20", "90", "40", "30", "12", "24",
		"100000001-100000999", "200000001-200000999", "300000001-300000999", "400000001-400000999",
		"<b 0xc70000000108><r 8><b 0x00004100><r 4>", "(null)", "(null)", "(null)", "(null)"}
	if f.ObfRuntime != nil {
		names := []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"}
		for i, n := range names {
			if v, ok := f.ObfRuntime[n]; ok {
				obf[i] = v
			}
		}
	}
	head := strings.Join(append([]string{"cHJpdg==", ServerPublicKey, "443"}, obf...), "\t") + "\t(none)\t0\t0\t0\t0\t0\t0\toff\n"
	keys := make([]string, 0, len(f.Peers))
	for k := range f.Peers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(head)
	for _, k := range keys {
		p := f.Peers[k]
		psk := "(none)"
		if p.HasPSK {
			psk = "cHNr"
		}
		fmt.Fprintf(&b, "%s\t%s\t(none)\t%s\t%d\t0\t0\toff\n", k, psk, p.Allowed, p.Handshake)
	}
	return b.String()
}

// SetCalls — только вызовы `awg set`.
func (f *Fake) SetCalls() []Call {
	var out []Call
	for _, c := range f.Calls {
		if len(c.Args) > 1 && c.Args[1] == "set" {
			out = append(out, c)
		}
	}
	return out
}
