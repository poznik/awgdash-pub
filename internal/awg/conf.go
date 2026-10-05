// Package awg — адаптер к AmneziaWG: конфиги awg-quick, вывод `awg show dump`, проверка обфускации.
//
// Принцип: секция [Interface] хранится и переписывается байт в байт; панель владеет только [Peer].
package awg

import (
	"bytes"
	"fmt"
	"strings"
)

// ObfKeys — 12 параметров обфускации, которые обязаны совпадать в файле и в рантайме.
var ObfKeys = []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1"}

// Peer — одна секция [Peer].
type Peer struct {
	PublicKey           string
	PresharedKey        string
	AllowedIPs          []string
	Endpoint            string
	PersistentKeepalive string
	// Extra — прочие ключи в порядке появления (например AdvancedSecurity).
	Extra []KV
}

// KV — пара ключ/значение с сохранением порядка.
type KV struct{ Key, Value string }

// Conf — разобранный файл awg-quick.
type Conf struct {
	// Interface — секция [Interface] как есть, включая строку заголовка и комментарии.
	Interface []byte
	// Params — ключи секции [Interface] (последнее значение при повторе). PrivateKey сюда попадает — не логировать.
	Params map[string]string
	Peers  []Peer
}

// Parse разбирает текст конфига. Секция [Interface] обязана быть первой и единственной.
func Parse(b []byte) (*Conf, error) {
	lines := strings.Split(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n")
	c := &Conf{Params: map[string]string{}}
	section := ""
	var ifaceLines []string
	var cur *Peer
	flush := func() {
		if cur != nil {
			c.Peers = append(c.Peers, *cur)
			cur = nil
		}
	}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch name {
			case "interface":
				if section != "" {
					return nil, fmt.Errorf("вторая секция [Interface]")
				}
				section = "interface"
				ifaceLines = append(ifaceLines, raw)
			case "peer":
				if section == "" {
					return nil, fmt.Errorf("[Peer] раньше [Interface]")
				}
				flush()
				section = "peer"
				cur = &Peer{}
			default:
				return nil, fmt.Errorf("неизвестная секция [%s]", name)
			}
			continue
		}
		switch section {
		case "":
			if line != "" && !strings.HasPrefix(line, "#") {
				return nil, fmt.Errorf("текст до [Interface]: %q", line)
			}
		case "interface":
			ifaceLines = append(ifaceLines, raw)
			if k, v, ok := splitKV(line); ok {
				c.Params[k] = v
			}
		case "peer":
			k, v, ok := splitKV(line)
			if !ok {
				continue
			}
			switch strings.ToLower(k) {
			case "publickey":
				cur.PublicKey = v
			case "presharedkey":
				cur.PresharedKey = v
			case "allowedips":
				for _, p := range strings.Split(v, ",") {
					if p = strings.TrimSpace(p); p != "" {
						cur.AllowedIPs = append(cur.AllowedIPs, p)
					}
				}
			case "endpoint":
				cur.Endpoint = v
			case "persistentkeepalive":
				cur.PersistentKeepalive = v
			default:
				cur.Extra = append(cur.Extra, KV{k, v})
			}
		}
	}
	flush()
	if section == "" {
		return nil, fmt.Errorf("нет секции [Interface]")
	}
	// Хвостовые пустые строки секции Interface убираем — их добавит Render.
	for len(ifaceLines) > 0 && strings.TrimSpace(ifaceLines[len(ifaceLines)-1]) == "" {
		ifaceLines = ifaceLines[:len(ifaceLines)-1]
	}
	c.Interface = []byte(strings.Join(ifaceLines, "\n") + "\n")
	for _, p := range c.Peers {
		if p.PublicKey == "" {
			return nil, fmt.Errorf("[Peer] без PublicKey")
		}
	}
	return c, nil
}

func splitKV(line string) (string, string, bool) {
	if line == "" || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	k, v, ok := strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(k), strings.TrimSpace(v), true
}

// Render собирает файл: Interface без изменений, затем пиры в каноническом виде.
func (c *Conf) Render() []byte {
	var b bytes.Buffer
	b.Write(c.Interface)
	for _, p := range c.Peers {
		b.WriteString("\n[Peer]\n")
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		if len(p.AllowedIPs) > 0 {
			fmt.Fprintf(&b, "AllowedIPs = %s\n", strings.Join(p.AllowedIPs, ", "))
		}
		if p.Endpoint != "" {
			fmt.Fprintf(&b, "Endpoint = %s\n", p.Endpoint)
		}
		if p.PersistentKeepalive != "" {
			fmt.Fprintf(&b, "PersistentKeepalive = %s\n", p.PersistentKeepalive)
		}
		for _, kv := range p.Extra {
			fmt.Fprintf(&b, "%s = %s\n", kv.Key, kv.Value)
		}
	}
	return b.Bytes()
}

// Param возвращает значение ключа секции [Interface] без учёта регистра ключа.
func (c *Conf) Param(key string) string {
	for k, v := range c.Params {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

// Obfuscation — 12 параметров из файла, нормализованные (отсутствующий = "").
func (c *Conf) Obfuscation() map[string]string {
	m := make(map[string]string, len(ObfKeys))
	for _, k := range ObfKeys {
		m[k] = NormalizeObf(k, c.Param(k))
	}
	return m
}

// NormalizeObf приводит значение параметра к сравнимому виду: "(null)"/"0"/пусто для I-пакетов = "",
// пробелы по краям убраны. Ноль у остальных параметров сохраняется: клиентский конфиг собирается
// из этих же значений, а строку «S3 = 0» из выдачи убирать нельзя — люди живут с ней в файлах.
func NormalizeObf(key, v string) string {
	v = strings.TrimSpace(v)
	if v == "(null)" || v == "(none)" {
		return ""
	}
	if strings.HasPrefix(key, "I") && v == "0" {
		return ""
	}
	return v
}

// SaveConfigEnabled — true, если в конфиге SaveConfig = true (панель с таким интерфейсом не работает).
func (c *Conf) SaveConfigEnabled() bool {
	return strings.EqualFold(c.Param("SaveConfig"), "true")
}

// FindPeer возвращает указатель на пир по публичному ключу или nil.
func (c *Conf) FindPeer(pub string) *Peer {
	for i := range c.Peers {
		if c.Peers[i].PublicKey == pub {
			return &c.Peers[i]
		}
	}
	return nil
}
