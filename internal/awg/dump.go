package awg

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// InterfaceDump — первая строка `awg show <if> dump`. Приватный ключ не сохраняется.
type InterfaceDump struct {
	PublicKey  string
	ListenPort int
	// Obf — 12 параметров обфускации, нормализованные (ключи как в ObfKeys). Для чистого WireGuard пусто.
	Obf map[string]string
	// Extra — поля после I5 (параметры AWG 3.x: S5?/ContentPaddingAddition/Rekey*/…), как есть.
	Extra  []string
	FwMark string
	IsAWG  bool
}

// PeerDump — строка пира из `awg show <if> dump`.
type PeerDump struct {
	PublicKey       string
	HasPSK          bool
	Endpoint        string
	AllowedIPs      []string
	LatestHandshake time.Time // нулевое время — хендшейка не было
	Rx, Tx          uint64
	Keepalive       int
}

// Online — хендшейк не старше порога (SPEC FR-6.2: 180 с).
func (p PeerDump) Online(now time.Time, threshold time.Duration) bool {
	return !p.LatestHandshake.IsZero() && now.Sub(p.LatestHandshake) <= threshold
}

// ParseDump разбирает вывод `awg show <if> dump` (поля разделены табуляцией — в I1 есть пробелы).
func ParseDump(out string) (*InterfaceDump, []PeerDump, error) {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return nil, nil, fmt.Errorf("пустой dump")
	}
	f := strings.Split(lines[0], "\t")
	id := &InterfaceDump{Obf: map[string]string{}}
	switch {
	case len(f) >= 19:
		id.IsAWG = true
		id.PublicKey = f[1]
		id.ListenPort, _ = strconv.Atoi(f[2])
		names := []string{"Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"}
		for i, n := range names {
			id.Obf[n] = NormalizeObf(n, f[3+i])
		}
		if len(f) > 19 {
			id.Extra = append([]string(nil), f[19:len(f)-1]...)
			id.FwMark = f[len(f)-1]
		}
	case len(f) == 4:
		id.PublicKey = f[1]
		id.ListenPort, _ = strconv.Atoi(f[2])
		id.FwMark = f[3]
	default:
		return nil, nil, fmt.Errorf("строка интерфейса: %d полей, ожидалось 4 или ≥19", len(f))
	}
	var peers []PeerDump
	for n, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		p := strings.Split(line, "\t")
		if len(p) < 8 {
			return nil, nil, fmt.Errorf("строка пира %d: %d полей, ожидалось 8", n+1, len(p))
		}
		pd := PeerDump{PublicKey: p[0], HasPSK: p[1] != "(none)"}
		if p[2] != "(none)" {
			pd.Endpoint = p[2]
		}
		if p[3] != "(none)" {
			for _, a := range strings.Split(p[3], ",") {
				if a = strings.TrimSpace(a); a != "" {
					pd.AllowedIPs = append(pd.AllowedIPs, a)
				}
			}
		}
		if ts, err := strconv.ParseInt(p[4], 10, 64); err == nil && ts > 0 {
			pd.LatestHandshake = time.Unix(ts, 0)
		}
		pd.Rx, _ = strconv.ParseUint(p[5], 10, 64)
		pd.Tx, _ = strconv.ParseUint(p[6], 10, 64)
		if p[7] != "off" {
			pd.Keepalive, _ = strconv.Atoi(p[7])
		}
		peers = append(peers, pd)
	}
	return id, peers, nil
}

// Obfuscation12 — только 12 сравниваемых параметров из рантайма.
func (d *InterfaceDump) Obfuscation12() map[string]string {
	m := make(map[string]string, len(ObfKeys))
	for _, k := range ObfKeys {
		m[k] = d.Obf[k]
	}
	return m
}
