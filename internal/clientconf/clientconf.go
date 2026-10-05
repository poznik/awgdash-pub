// Package clientconf — сборка клиентского конфига AmneziaWG и его вариантов (SPEC §6.4).
//
// Конфиг собирается в момент выдачи: панель хранит ключи и переопределения, а не готовый текст.
package clientconf

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/poznik/awgdash-pub/internal/awg"
	"github.com/poznik/awgdash-pub/internal/store"
)

// RouterKeepalive — keepalive для пресета router (FR-4.3).
const RouterKeepalive = 25

// privateNets — RFC1918: их пресет router оставляет локальной сети за роутером.
var privateNets = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
}

// localNets — то, что роутер не должен уводить в туннель вдобавок к RFC1918:
// multicast и зарезервированное (224.0.0.0/3). Иначе за роутером ломаются mDNS/Bonjour и SSDP/DLNA.
var localNets = append(append([]netip.Prefix{}, privateNets...), netip.MustParsePrefix("224.0.0.0/3"))

// Build собирает текст конфига устройства для выбранного варианта endpoint.
func Build(iface store.Interface, d store.Device, ep store.Endpoint) (string, error) {
	if d.PrivateKey == "" {
		return "", fmt.Errorf("у устройства %q нет приватного ключа (импортировано без него?)", d.Name)
	}
	if iface.ServerPublicKey == "" {
		return "", fmt.Errorf("у интерфейса %s не известен публичный ключ сервера", iface.Name)
	}
	if ep.Host == "" || ep.Port == 0 {
		return "", fmt.Errorf("не задан endpoint интерфейса %s", iface.Name)
	}
	allowed, err := AllowedIPs(iface, d)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", d.PrivateKey)
	fmt.Fprintf(&b, "Address = %s/32\n", strings.TrimSpace(d.Address))
	if dns := firstNonEmpty(d.Overrides.DNS, iface.DefaultDNS); dns != "" {
		fmt.Fprintf(&b, "DNS = %s\n", dns)
	}
	if mtu := firstPositive(d.Overrides.MTU, iface.MTU); mtu > 0 {
		fmt.Fprintf(&b, "MTU = %d\n", mtu)
	}
	// Обфускация — из интерфейса, в порядке awg.ObfKeys. Пустые и «0» у I-пакетов не выводятся (FR-4.2):
	// KeeneticOS отвергает конфиг со строкой `I2 = 0`.
	for _, k := range awg.ObfKeys {
		if v := awg.NormalizeObf(k, iface.Obfuscation[k]); v != "" {
			fmt.Fprintf(&b, "%s = %s\n", k, v)
		}
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", iface.ServerPublicKey)
	if d.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", d.PresharedKey)
	}
	fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(allowed, ", "))
	fmt.Fprintf(&b, "Endpoint = %s:%d\n", ep.Host, ep.Port)
	if ka := Keepalive(iface, d); ka > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", ka)
	}
	return b.String(), nil
}

// Keepalive — переопределение устройства, иначе 25 для роутера, иначе умолчание интерфейса.
func Keepalive(iface store.Interface, d store.Device) int {
	if d.Overrides.Keepalive > 0 {
		return d.Overrides.Keepalive
	}
	if d.Preset == store.PresetRouter {
		return RouterKeepalive
	}
	return iface.DefaultKeepalive
}

// AllowedIPs возвращает список префиксов для [Peer] по пресету и переопределениям (FR-4.3).
func AllowedIPs(iface store.Interface, d store.Device) ([]string, error) {
	if v := strings.TrimSpace(d.Overrides.AllowedIPs); v != "" {
		return splitList(v), nil
	}
	switch d.Preset {
	case store.PresetRouter:
		return RouterAllowedIPs(iface.Subnet)
	case store.PresetCustom:
		if v := strings.TrimSpace(iface.DefaultAllowedIPs); v != "" {
			return splitList(v), nil
		}
		return nil, fmt.Errorf("пресет custom без переопределения AllowedIPs")
	default: // phone
		if v := strings.TrimSpace(iface.DefaultAllowedIPs); v != "" {
			return splitList(v), nil
		}
		return []string{"0.0.0.0/0"}, nil
	}
}

// RouterAllowedIPs — весь интернет минус RFC1918, плюс подсеть VPN обратно:
// за роутером остаётся своя локальная сеть, но адреса самого туннеля доступны.
func RouterAllowedIPs(subnet string) ([]string, error) {
	rest := subtract(netip.MustParsePrefix("0.0.0.0/0"), localNets)
	if p, err := netip.ParsePrefix(strings.TrimSpace(subnet)); err == nil && p.Addr().Is4() {
		p = p.Masked()
		if isPrivate(p) {
			rest = append(rest, p)
		}
	} else if strings.TrimSpace(subnet) != "" && err != nil {
		return nil, fmt.Errorf("подсеть интерфейса %q: %w", subnet, err)
	}
	sort.Slice(rest, func(i, j int) bool {
		if c := rest[i].Addr().Compare(rest[j].Addr()); c != 0 {
			return c < 0
		}
		return rest[i].Bits() < rest[j].Bits()
	})
	out := make([]string, 0, len(rest))
	for _, p := range rest {
		out = append(out, p.String())
	}
	return out, nil
}

// subtract вычитает из base все префиксы excl, разбивая base пополам, пока куски не станут
// либо целиком исключёнными, либо свободными.
func subtract(base netip.Prefix, excl []netip.Prefix) []netip.Prefix {
	for _, e := range excl {
		if covers(e, base) {
			return nil
		}
	}
	hit := false
	for _, e := range excl {
		if base.Overlaps(e) {
			hit = true
			break
		}
	}
	if !hit {
		return []netip.Prefix{base}
	}
	lo, hi, ok := split(base)
	if !ok {
		return nil // /32 внутри исключения делить некуда
	}
	return append(subtract(lo, excl), subtract(hi, excl)...)
}

// covers — outer полностью содержит inner.
func covers(outer, inner netip.Prefix) bool {
	return outer.Bits() <= inner.Bits() && outer.Contains(inner.Addr())
}

// split делит префикс на две половины.
func split(p netip.Prefix) (netip.Prefix, netip.Prefix, bool) {
	if p.Bits() >= 32 {
		return netip.Prefix{}, netip.Prefix{}, false
	}
	bits := p.Bits() + 1
	lo := netip.PrefixFrom(p.Addr(), bits).Masked()
	b := lo.Addr().As4()
	b[(bits-1)/8] |= 1 << (7 - (bits-1)%8)
	hi := netip.PrefixFrom(netip.AddrFrom4(b), bits)
	return lo, hi, true
}

func isPrivate(p netip.Prefix) bool {
	for _, e := range privateNets {
		if covers(e, p) {
			return true
		}
	}
	return false
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func firstPositive(vs ...int) int {
	for _, v := range vs {
		if v > 0 {
			return v
		}
	}
	return 0
}

// FileName — имя файла для скачивания: «пользователь-устройство.conf» (FR-4.5).
func FileName(user, device string) string {
	clean := func(s string) string {
		s = strings.TrimSpace(s)
		var b strings.Builder
		for _, r := range s {
			switch {
			case r == ' ' || r == '/' || r == '\\':
				b.WriteRune('-')
			case r < 0x20 || r == '"' || r == ':' || r == '*' || r == '?' || r == '<' || r == '>' || r == '|':
				// пропускаем
			default:
				b.WriteRune(r)
			}
		}
		return strings.Trim(b.String(), "-.")
	}
	name := clean(user) + "-" + clean(device)
	if name == "-" {
		name = "awgdash"
	}
	return name + ".conf"
}

// Endpoints возвращает варианты endpoint интерфейса; первым — основной (FR-1.7).
// Если варианты не заданы, собирается один из наблюдаемых фактов интерфейса.
func Endpoints(iface store.Interface) []store.Endpoint {
	out := append([]store.Endpoint(nil), iface.Endpoints...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Primary && !out[j].Primary })
	if len(out) == 0 && iface.ListenPort > 0 {
		out = append(out, store.Endpoint{Label: "основной", Host: "", Port: iface.ListenPort, Primary: true})
	}
	return out
}

// EndpointByLabel ищет вариант по метке; пустая метка — основной вариант.
func EndpointByLabel(iface store.Interface, label string) (store.Endpoint, error) {
	eps := Endpoints(iface)
	if len(eps) == 0 {
		return store.Endpoint{}, fmt.Errorf("у интерфейса %s не задан ни один endpoint", iface.Name)
	}
	if label == "" {
		return eps[0], nil
	}
	for _, e := range eps {
		if e.Label == label {
			return e, nil
		}
	}
	return store.Endpoint{}, fmt.Errorf("вариант endpoint %q не найден", label)
}

// ParsePort — вспомогательное: порт из строки «host:port».
func ParsePort(s string) int {
	_, port, ok := strings.Cut(s, ":")
	if !ok {
		return 0
	}
	n, _ := strconv.Atoi(port)
	return n
}
