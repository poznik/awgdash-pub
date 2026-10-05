package awg

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// BackupsKept — сколько прошлых версий конфига хранится рядом (SPEC §4.3).
const BackupsKept = 5

// PeerSpec — желаемое состояние пира на сервере. Приватных ключей клиента здесь нет и быть не может.
type PeerSpec struct {
	PublicKey    string
	PresharedKey string   // пусто = не трогать, если ClearPSK не задан
	AllowedIPs   []string // на сервере это адрес устройства: 10.20.0.7/32
	ClearPSK     bool     // снять PSK, который стоял раньше
}

// wgKeyRe — ключ WireGuard в base64: 43 значащих символа и «=». Строка ровно этого вида,
// без пробелов и переводов строки.
var wgKeyRe = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

// Validate проверяет, что пир можно безопасно записать в файл конфига. Значение с переводом
// строки дописало бы в файл произвольные строки [Peer], а неверный ключ или адрес пережили бы
// запись и всплыли перезагрузкой, когда awg-quick не поднимет интерфейс. Ключи приходят и из
// API узла (путь PUT декодируется, `%0A` проходит), поэтому проверка живёт в самой точке записи,
// а не только у вызывающих (FR-1.3).
func (p PeerSpec) Validate() error {
	if !wgKeyRe.MatchString(p.PublicKey) {
		return fmt.Errorf("публичный ключ пира не в формате WireGuard")
	}
	if p.PresharedKey != "" && !wgKeyRe.MatchString(p.PresharedKey) {
		return fmt.Errorf("preshared-ключ пира не в формате WireGuard")
	}
	if len(p.AllowedIPs) == 0 {
		return fmt.Errorf("пир без allowed-ips")
	}
	for _, a := range p.AllowedIPs {
		if _, err := netip.ParsePrefix(strings.TrimSpace(a)); err != nil {
			return fmt.Errorf("allowed-ips %q: не префикс", a)
		}
	}
	return nil
}

// SetPeer выполняет `awg set <iface> peer <pub> [preshared-key /dev/stdin] allowed-ips …`.
// PSK передаётся через stdin: в командной строке он был бы виден в /proc.
func (t Tool) SetPeer(ctx context.Context, iface string, p PeerSpec) error {
	if p.PublicKey == "" {
		return fmt.Errorf("awg set: пустой публичный ключ")
	}
	args := []string{"set", iface, "peer", p.PublicKey}
	var stdin []byte
	switch {
	case p.PresharedKey != "":
		args = append(args, "preshared-key", "/dev/stdin")
		stdin = []byte(p.PresharedKey + "\n")
	case p.ClearPSK:
		args = append(args, "preshared-key", "/dev/stdin")
		stdin = []byte("\n")
	}
	if len(p.AllowedIPs) > 0 {
		args = append(args, "allowed-ips", strings.Join(p.AllowedIPs, ","))
	}
	_, err := t.R.Run(ctx, stdin, t.Bin, args...)
	return err
}

// RemovePeer выполняет `awg set <iface> peer <pub> remove`.
func (t Tool) RemovePeer(ctx context.Context, iface, pub string) error {
	if pub == "" {
		return fmt.Errorf("awg set remove: пустой публичный ключ")
	}
	_, err := t.R.Run(ctx, nil, t.Bin, "set", iface, "peer", pub, "remove")
	return err
}

// WriteConf сохраняет конфиг атомарно: временный файл рядом → fsync → rename → fsync каталога.
// Прежняя версия уходит в backupDir; там хранятся BackupsKept последних. Владелец и права
// исходного файла сохраняются: конфиг остаётся root:0600, даже когда панель работает не от root.
func WriteConf(path, backupDir string, c *Conf, now time.Time) error {
	return WriteRaw(path, backupDir, c.Render(), now)
}

// WriteRaw — та же атомарная запись для готового содержимого: нужна для отката к прежней версии.
func WriteRaw(path, backupDir string, body []byte, now time.Time) error {
	dir := filepath.Dir(path)
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("конфиг %s: %w", path, err)
	}
	if backupDir != "" {
		if err := backup(path, backupDir, now); err != nil {
			return err
		}
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("временный файл рядом с %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // при успехе rename уже унёс файл, Remove просто не найдёт его
	if _, err := tmp.Write(body); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpName, info.Mode().Perm()); err != nil {
		return err
	}
	if err := preserveOwner(info, tmpName); err != nil {
		return fmt.Errorf("владелец %s: %w", path, err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return syncDir(dir)
}

// backup копирует текущий файл в backupDir и подчищает старые версии.
func backup(path, backupDir string, now time.Time) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		return err
	}
	base := filepath.Base(path)
	dst := filepath.Join(backupDir, fmt.Sprintf("%s.%s", base, now.UTC().Format("20060102T150405.000")))
	if err := os.WriteFile(dst, body, 0o600); err != nil {
		return err
	}
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return err
	}
	var mine []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), base+".") {
			mine = append(mine, e.Name())
		}
	}
	if len(mine) <= BackupsKept {
		return nil
	}
	sort.Strings(mine) // имя содержит время в лексикографически сортируемом виде
	for _, name := range mine[:len(mine)-BackupsKept] {
		if err := os.Remove(filepath.Join(backupDir, name)); err != nil {
			return err
		}
	}
	return nil
}

// syncDir сбрасывает запись каталога, чтобы rename пережил внезапную перезагрузку.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil && !isNotSupported(err) {
		return err
	}
	return nil
}

// ReplacePeers заменяет секции [Peer] на желаемые, оставляя [Interface] байт в байт.
// Порядок пиров — по AllowedIPs, чтобы diff файла между версиями оставался читаемым.
func (c *Conf) ReplacePeers(peers []Peer) {
	sorted := append([]Peer(nil), peers...)
	sort.SliceStable(sorted, func(i, j int) bool { return peerKey(sorted[i]) < peerKey(sorted[j]) })
	c.Peers = sorted
}

func peerKey(p Peer) string {
	if len(p.AllowedIPs) > 0 {
		return addrSortKey(p.AllowedIPs[0]) + "|" + p.PublicKey
	}
	return "~|" + p.PublicKey
}

// addrSortKey превращает 10.20.0.9/32 в 010.020.000.009, чтобы сортировка шла по числам.
func addrSortKey(s string) string {
	host, _, _ := strings.Cut(strings.TrimSpace(s), "/")
	parts := strings.Split(host, ".")
	if len(parts) != 4 {
		return host
	}
	for i, p := range parts {
		for len(p) < 3 {
			p = "0" + p
		}
		parts[i] = p
	}
	return strings.Join(parts, ".")
}
