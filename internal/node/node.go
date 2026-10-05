// Package node — агент на сервере с AmneziaWG: обнаружение интерфейсов, чтение дампов, сверка обфускации,
// метрики хоста. В фазе 1 живёт в одном процессе с хабом; HTTP API (api.go) — та же граница, что для удалённых узлов.
package node

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/poznik/awgdash-pub/internal/awg"
	"github.com/poznik/awgdash-pub/internal/hostmetrics"
)

// Node — локальный узел.
type Node struct {
	ConfDir string
	Tool    awg.Tool
	Runner  awg.Runner
	Metrics *hostmetrics.Collector
	// ForeignManagers — чужие менеджеры пиров, активность которых запрещает запись (guard, FR-1.3):
	// systemd-юнит или контейнер записью `docker:<имя>`.
	ForeignManagers []string
	// BackupDir — куда уходят прошлые версии конфигов перед записью; пусто = не хранить.
	BackupDir string

	mu      sync.Mutex
	confs   map[string]cachedConf
	writeMu sync.Mutex // запись в интерфейс — по одной за раз
}

// ConfPath — путь к файлу конфига интерфейса. Экспортирован ради копий: путь из БД может
// быть ещё не заполнен, а файл забрать надо.
func (n *Node) ConfPath(name string) string { return n.confPath(name) }

// confPath — путь к файлу конфига интерфейса.
func (n *Node) confPath(name string) string { return filepath.Join(n.ConfDir, name+".conf") }

type cachedConf struct {
	mtime time.Time
	size  int64
	conf  *awg.Conf
}

// New создаёт узел.
func New(confDir, awgBin string, r awg.Runner, foreign []string) *Node {
	run := func(ctx context.Context, name string, args ...string) (string, error) {
		out, err := r.Run(ctx, nil, name, args...)
		return string(out), err
	}
	return &Node{ConfDir: confDir, Tool: awg.Tool{Bin: awgBin, R: r}, Runner: r, Metrics: hostmetrics.New("", run), ForeignManagers: foreign, confs: map[string]cachedConf{}}
}

// InterfaceInfo — описание интерфейса для хаба и API (без приватных ключей).
type InterfaceInfo struct {
	Name            string            `json:"name"`
	ConfPath        string            `json:"conf_path"`
	ConfMtime       time.Time         `json:"conf_mtime"`
	Address         string            `json:"address"`
	Subnet          string            `json:"subnet"`
	ListenPort      int               `json:"listen_port"`
	MTU             int               `json:"mtu"`
	SaveConfig      bool              `json:"save_config"`
	UnitActive      bool              `json:"unit_active"`
	ServerPublicKey string            `json:"server_public_key"`
	IsAWG           bool              `json:"is_awg"`
	Obfuscation     map[string]string `json:"obfuscation"`
	ConfPeers       int               `json:"conf_peers"`
	DumpError       string            `json:"dump_error,omitempty"`
}

// Discover перечисляет конфиги в каталоге и собирает факты по каждому интерфейсу.
// Ошибка дампа (нет прав, интерфейс не поднят) попадает в DumpError, остальные факты всё равно возвращаются.
func (n *Node) Discover(ctx context.Context) ([]InterfaceInfo, error) {
	entries, err := os.ReadDir(n.ConfDir)
	if err != nil {
		return nil, fmt.Errorf("каталог конфигов %s: %w", n.ConfDir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
			names = append(names, strings.TrimSuffix(e.Name(), ".conf"))
		}
	}
	sort.Strings(names)
	out := make([]InterfaceInfo, 0, len(names))
	for _, name := range names {
		info, err := n.Interface(ctx, name)
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, nil
}

// validName пропускает только имена интерфейсов: имя приходит в API из пути запроса и
// превращается в путь файла, поэтому «..» и слэши отсекаются до обращения к диску.
func validName(name string) error {
	if name == "" || len(name) > 32 {
		return fmt.Errorf("имя интерфейса %q: ожидается от 1 до 32 символов", name)
	}
	for _, r := range name {
		ok := r == '-' || r == '_' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
		if !ok {
			return fmt.Errorf("имя интерфейса %q: допустимы буквы, цифры, дефис и подчёркивание", name)
		}
	}
	return nil
}

// Conf читает и кэширует конфиг интерфейса (перечитывается при смене mtime/размера).
func (n *Node) Conf(name string) (*awg.Conf, time.Time, error) {
	if err := validName(name); err != nil {
		return nil, time.Time{}, err
	}
	path := n.confPath(name)
	st, err := os.Stat(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	n.mu.Lock()
	c, ok := n.confs[name]
	n.mu.Unlock()
	if ok && c.mtime.Equal(st.ModTime()) && c.size == st.Size() {
		return c.conf, c.mtime, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, time.Time{}, err
	}
	conf, err := awg.Parse(b)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("%s: %w", path, err)
	}
	n.mu.Lock()
	n.confs[name] = cachedConf{mtime: st.ModTime(), size: st.Size(), conf: conf}
	n.mu.Unlock()
	return conf, st.ModTime(), nil
}

// Interface собирает факты одного интерфейса: конфиг + юнит + дамп.
func (n *Node) Interface(ctx context.Context, name string) (InterfaceInfo, error) {
	conf, mtime, err := n.Conf(name)
	if err != nil {
		return InterfaceInfo{}, err
	}
	info := InterfaceInfo{Name: name, ConfPath: n.confPath(name), ConfMtime: mtime, SaveConfig: conf.SaveConfigEnabled(), ConfPeers: len(conf.Peers), Obfuscation: conf.Obfuscation()}
	info.Address = conf.Param("Address")
	info.Subnet = subnetOf(info.Address)
	fmt.Sscanf(conf.Param("ListenPort"), "%d", &info.ListenPort)
	fmt.Sscanf(conf.Param("MTU"), "%d", &info.MTU)
	info.UnitActive = awg.UnitActive(ctx, n.Runner, "awg-quick@"+name)
	if id, _, err := n.Tool.ShowDump(ctx, name); err != nil {
		info.DumpError = err.Error()
	} else {
		info.ServerPublicKey = id.PublicKey
		info.IsAWG = id.IsAWG
		if id.ListenPort > 0 {
			info.ListenPort = id.ListenPort
		}
	}
	return info, nil
}

// Dump возвращает пиров рантайма.
func (n *Node) Dump(ctx context.Context, name string) (*awg.InterfaceDump, []awg.PeerDump, error) {
	return n.Tool.ShowDump(ctx, name)
}

// ConfPeers возвращает пиров из файла.
func (n *Node) ConfPeers(name string) ([]awg.Peer, error) {
	conf, _, err := n.Conf(name)
	if err != nil {
		return nil, err
	}
	return conf.Peers, nil
}

// Verify сверяет 12 параметров обфускации файла и рантайма.
func (n *Node) Verify(ctx context.Context, name string) (awg.VerifyResult, error) {
	conf, _, err := n.Conf(name)
	if err != nil {
		return awg.VerifyResult{}, err
	}
	id, _, err := n.Tool.ShowDump(ctx, name)
	if err != nil {
		return awg.VerifyResult{}, err
	}
	return awg.Verify(conf, id), nil
}

// ForeignManagerActive возвращает имя активного чужого менеджера пиров или пустую строку.
func (n *Node) ForeignManagerActive(ctx context.Context) string {
	for _, u := range n.ForeignManagers {
		if u != "" && awg.ManagerActive(ctx, n.Runner, u) {
			return u
		}
	}
	return ""
}

// Health — сводка узла.
type Health struct {
	Version        string   `json:"version"`
	API            int      `json:"api"`
	AWGVersion     string   `json:"awg_version"`
	Interfaces     []string `json:"interfaces"`
	ForeignManager string   `json:"foreign_manager,omitempty"`
	// Buffered — сколько выборок узел держит для хаба и с какого момента (FR-10.4).
	Buffered     int       `json:"buffered,omitempty"`
	BufferedFrom time.Time `json:"buffered_from,omitempty"`
}

func subnetOf(addr string) string {
	// 10.20.0.1/16 → 10.20.0.0/16 (грубо, для отображения; точный расчёт — при выдаче адресов в M2).
	ip, mask, ok := strings.Cut(strings.TrimSpace(addr), "/")
	if !ok {
		return addr
	}
	var a, b, c, d, bits int
	if _, err := fmt.Sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d); err != nil {
		return addr
	}
	fmt.Sscanf(mask, "%d", &bits)
	v := uint32(a)<<24 | uint32(b)<<16 | uint32(c)<<8 | uint32(d)
	if bits > 0 && bits < 32 {
		v &= ^uint32(0) << (32 - bits)
	}
	return fmt.Sprintf("%d.%d.%d.%d/%d", v>>24, v>>16&255, v>>8&255, v&255, bits)
}

// ConfRaw читает файл конфига интерфейса как есть. Нужен копиям (в архив кладётся тот же
// файл, что лежит на диске) и удалённому хабу, которому недоступна файловая система узла.
func (n *Node) ConfRaw(name string) ([]byte, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	return os.ReadFile(n.confPath(name))
}
