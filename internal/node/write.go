package node

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/awg"
)

// GuardError — запись отклонена охранной проверкой (FR-1.3). Отдельный тип: хаб пишет по нему событие `guard`.
type GuardError struct{ Reason string }

func (e *GuardError) Error() string {
	return "запись в интерфейс отклонена: " + e.Reason
}

// Guard проверяет, что писать в интерфейс сейчас безопасно: чужой менеджер пиров неактивен,
// SaveConfig=false (иначе `awg-quick down` перепишет файл рантаймом) и обфускация файла
// совпадает с рантаймом 12/12 (SPEC §4.3).
func (n *Node) Guard(ctx context.Context, iface string) error {
	if fm := n.ForeignManagerActive(ctx); fm != "" {
		return &GuardError{Reason: "активен чужой менеджер пиров " + fm}
	}
	conf, _, err := n.Conf(iface)
	if err != nil {
		return err
	}
	if conf.SaveConfigEnabled() {
		return &GuardError{Reason: "в конфиге " + iface + " задан SaveConfig = true"}
	}
	res, err := n.Verify(ctx, iface)
	if err != nil {
		return fmt.Errorf("сверка обфускации %s: %w", iface, err)
	}
	if !res.OK {
		return &GuardError{Reason: fmt.Sprintf("обфускация %s расходится: %d/%d, %v", iface, res.Matched, res.Total, res.Diffs)}
	}
	return nil
}

// ApplyPeer приводит один пир к желаемому состоянию: сначала файл, затем рантайм.
// При ошибке рантайма файл возвращается к прежнему содержимому — рассинхрона не остаётся.
func (n *Node) ApplyPeer(ctx context.Context, iface string, spec awg.PeerSpec) error {
	if err := spec.Validate(); err != nil {
		return err
	}
	return n.mutate(ctx, iface, func(c *awg.Conf) error {
		peer := awg.Peer{PublicKey: spec.PublicKey, PresharedKey: spec.PresharedKey, AllowedIPs: spec.AllowedIPs}
		if cur := c.FindPeer(spec.PublicKey); cur != nil {
			if spec.PresharedKey == "" && !spec.ClearPSK {
				peer.PresharedKey = cur.PresharedKey
			}
			peer.Extra = cur.Extra
		}
		peers := make([]awg.Peer, 0, len(c.Peers)+1)
		for _, p := range c.Peers {
			if p.PublicKey != spec.PublicKey {
				peers = append(peers, p)
			}
		}
		c.ReplacePeers(append(peers, peer))
		return nil
	}, func() error {
		return n.Tool.SetPeer(ctx, iface, spec)
	})
}

// RemovePeer снимает пир с интерфейса и убирает его из файла.
func (n *Node) RemovePeer(ctx context.Context, iface, pub string) error {
	return n.mutate(ctx, iface, func(c *awg.Conf) error {
		peers := make([]awg.Peer, 0, len(c.Peers))
		for _, p := range c.Peers {
			if p.PublicKey != pub {
				peers = append(peers, p)
			}
		}
		c.ReplacePeers(peers)
		return nil
	}, func() error {
		return n.Tool.RemovePeer(ctx, iface, pub)
	})
}

// ReconcileResult — что сделал Reconcile (SPEC §9).
type ReconcileResult struct {
	Added     []string `json:"added"`
	Updated   []string `json:"updated"`
	Removed   []string `json:"removed"`
	Untouched []string `json:"untouched"`
}

// Changed — было ли что-то изменено.
func (r ReconcileResult) Changed() bool {
	return len(r.Added)+len(r.Updated)+len(r.Removed) > 0
}

// Reconcile приводит интерфейс к списку желаемых пиров: лишние снимаются, недостающие ставятся,
// изменившиеся обновляются. Пустой список при непустом рантайме требует allowEmpty — защита от
// вызова с недособранным желаемым состоянием (это сняло бы всех пиров разом).
func (n *Node) Reconcile(ctx context.Context, iface string, desired []awg.PeerSpec, allowEmpty bool) (ReconcileResult, error) {
	res, apply, err := n.PlanReconcile(ctx, iface, desired, allowEmpty)
	if err != nil {
		return res, err
	}
	if !res.Changed() {
		// Файл всё равно может расходиться с желаемым — приводим его к списку.
		return res, n.mutate(ctx, iface, func(c *awg.Conf) error {
			c.ReplacePeers(peersOf(desired, c))
			return nil
		}, nil)
	}
	err = n.mutate(ctx, iface, func(c *awg.Conf) error {
		c.ReplacePeers(peersOf(desired, c))
		return nil
	}, func() error {
		for _, pub := range res.Removed {
			if err := n.Tool.RemovePeer(ctx, iface, pub); err != nil {
				return err
			}
		}
		for _, spec := range apply {
			if err := n.Tool.SetPeer(ctx, iface, spec); err != nil {
				return err
			}
		}
		return nil
	})
	return res, err
}

// PlanReconcile считает, что нужно сделать, ничего не меняя: тот же расчёт использует Reconcile,
// поэтому «примерка» и запись не расходятся. Второе значение — что предстоит передать в `awg set`.
func (n *Node) PlanReconcile(ctx context.Context, iface string, desired []awg.PeerSpec, allowEmpty bool) (ReconcileResult, []awg.PeerSpec, error) {
	var res ReconcileResult
	for _, d := range desired {
		if err := d.Validate(); err != nil {
			return res, nil, fmt.Errorf("пир %s: %w", d.PublicKey, err)
		}
	}
	_, runtime, err := n.Dump(ctx, iface)
	if err != nil {
		return res, nil, err
	}
	if len(desired) == 0 && len(runtime) > 0 && !allowEmpty {
		return res, nil, &GuardError{Reason: fmt.Sprintf("желаемое состояние пусто, а на %s стоит пиров: %d", iface, len(runtime))}
	}
	cur := make(map[string]awg.PeerDump, len(runtime))
	for _, p := range runtime {
		cur[p.PublicKey] = p
	}
	want := make(map[string]awg.PeerSpec, len(desired))
	var apply []awg.PeerSpec
	for _, d := range desired {
		want[d.PublicKey] = d
		have, ok := cur[d.PublicKey]
		switch {
		case !ok:
			res.Added = append(res.Added, d.PublicKey)
			apply = append(apply, d)
		case !sameAllowed(have.AllowedIPs, d.AllowedIPs) || have.HasPSK != (d.PresharedKey != ""):
			spec := d
			spec.ClearPSK = have.HasPSK && d.PresharedKey == ""
			res.Updated = append(res.Updated, d.PublicKey)
			apply = append(apply, spec)
		default:
			res.Untouched = append(res.Untouched, d.PublicKey)
		}
	}
	for pub := range cur {
		if _, ok := want[pub]; !ok {
			res.Removed = append(res.Removed, pub)
		}
	}
	sort.Strings(res.Added)
	sort.Strings(res.Updated)
	sort.Strings(res.Removed)
	sort.Strings(res.Untouched)
	return res, apply, nil
}

// peersOf превращает желаемые спецификации в секции [Peer], сохраняя PSK и прочие ключи из файла,
// если в спецификации PSK не задан.
func peersOf(desired []awg.PeerSpec, c *awg.Conf) []awg.Peer {
	out := make([]awg.Peer, 0, len(desired))
	for _, d := range desired {
		p := awg.Peer{PublicKey: d.PublicKey, PresharedKey: d.PresharedKey, AllowedIPs: d.AllowedIPs}
		if cur := c.FindPeer(d.PublicKey); cur != nil {
			if d.PresharedKey == "" && !d.ClearPSK {
				p.PresharedKey = cur.PresharedKey
			}
			p.Extra = cur.Extra
		}
		out = append(out, p)
	}
	return out
}

// mutate — общий каркас записи: guard → файл (с бэкапом) → рантайм → verify.
// Ошибка рантайма откатывает файл; ошибка verify оставляет запись, но возвращает ошибку —
// расхождение обязано попасть к администратору, а не тихо исчезнуть.
func (n *Node) mutate(ctx context.Context, iface string, edit func(*awg.Conf) error, runtime func() error) error {
	if err := n.Guard(ctx, iface); err != nil {
		return err
	}
	n.writeMu.Lock()
	defer n.writeMu.Unlock()

	conf, _, err := n.Conf(iface)
	if err != nil {
		return err
	}
	path := n.confPath(iface)
	before, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	next := *conf
	next.Peers = append([]awg.Peer(nil), conf.Peers...)
	if err := edit(&next); err != nil {
		return err
	}
	body := next.Render()
	if string(body) != string(before) {
		if err := awg.WriteConf(path, n.BackupDir, &next, time.Now()); err != nil {
			return err
		}
	}
	if runtime != nil {
		if err := runtime(); err != nil {
			if string(body) != string(before) {
				if rb := awg.WriteRaw(path, "", before, time.Now()); rb != nil {
					return fmt.Errorf("%w; откат файла тоже не удался: %v", err, rb)
				}
			}
			return err
		}
	}
	res, verr := n.Verify(ctx, iface)
	if verr != nil {
		return fmt.Errorf("сверка после записи: %w", verr)
	}
	if !res.OK {
		return fmt.Errorf("после записи обфускация %s разошлась: %d/%d, %v", iface, res.Matched, res.Total, res.Diffs)
	}
	return nil
}

// sameAllowed сравнивает списки allowed-ips без учёта порядка и пробелов.
func sameAllowed(a, b []string) bool {
	norm := func(in []string) []string {
		out := make([]string, 0, len(in))
		for _, v := range in {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
		sort.Strings(out)
		return out
	}
	x, y := norm(a), norm(b)
	if len(x) != len(y) {
		return false
	}
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}
