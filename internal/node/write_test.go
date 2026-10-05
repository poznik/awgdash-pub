package node

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/poznik/awgdash-pub/internal/awg"
	"github.com/poznik/awgdash-pub/internal/awgtest"
)

func newTestNode(t *testing.T, f *awgtest.Fake) (*Node, string, string) {
	t.Helper()
	dir := t.TempDir()
	confDir := filepath.Join(dir, "etc")
	backupDir := filepath.Join(dir, "conf-backup")
	if err := os.MkdirAll(confDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path, err := awgtest.WriteConf(confDir, "awg-t0")
	if err != nil {
		t.Fatal(err)
	}
	n := New(confDir, "awg", f, []string{"wg-dashboard.service"})
	n.BackupDir = backupDir
	return n, path, backupDir
}

// ifaceSection возвращает секцию [Interface] файла: она обязана переживать запись байт в байт.
func ifaceSection(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := string(b)
	if i := strings.Index(body, "\n[Peer]"); i >= 0 {
		return body[:i]
	}
	return body
}

func TestApplyPeerWritesFileAndRuntime(t *testing.T) {
	ctx := context.Background()
	f := awgtest.New()
	n, path, backupDir := newTestNode(t, f)
	before := ifaceSection(t, path)

	spec := awg.PeerSpec{PublicKey: awgtest.KeyC, PresharedKey: awgtest.PSK, AllowedIPs: []string{"10.20.0.9/32"}}
	if err := n.ApplyPeer(ctx, "awg-t0", spec); err != nil {
		t.Fatal(err)
	}
	// Рантайм: пир поставлен, PSK ушёл через stdin, а не аргументом.
	if p, ok := f.Peers[awgtest.KeyC]; !ok || !p.HasPSK || p.Allowed != "10.20.0.9/32" {
		t.Fatalf("рантайм после ApplyPeer: %+v", f.Peers)
	}
	last := f.SetCalls()
	if len(last) != 1 {
		t.Fatalf("вызовов awg set: %d", len(last))
	}
	if strings.Contains(strings.Join(last[0].Args, " "), awgtest.PSK) {
		t.Fatalf("PSK попал в командную строку: %v", last[0].Args)
	}
	if strings.TrimSpace(last[0].Stdin) != awgtest.PSK {
		t.Fatalf("PSK не передан через stdin: %q", last[0].Stdin)
	}
	// Файл: секция [Interface] байт в байт, новый пир на месте, порядок по адресам.
	if got := ifaceSection(t, path); got != before {
		t.Fatalf("секция [Interface] изменилась:\n--- было ---\n%s\n--- стало ---\n%s", before, got)
	}
	body, _ := os.ReadFile(path)
	conf, err := awg.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(conf.Peers) != 3 {
		t.Fatalf("пиров в файле: %d", len(conf.Peers))
	}
	if conf.Peers[2].PublicKey != awgtest.KeyC || conf.Peers[2].PresharedKey != awgtest.PSK {
		t.Fatalf("новый пир в файле: %+v", conf.Peers[2])
	}
	if conf.Peers[0].PublicKey != awgtest.KeyA || conf.Peers[1].PublicKey != awgtest.KeyB {
		t.Fatal("порядок пиров не по адресам")
	}
	// Прежняя версия сохранена.
	entries, err := os.ReadDir(backupDir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("бэкапы: %v, err = %v", entries, err)
	}
	saved, _ := os.ReadFile(filepath.Join(backupDir, entries[0].Name()))
	if string(saved) != awgtest.ConfBody {
		t.Fatal("бэкап не совпадает с прежним файлом")
	}
}

func TestApplyPeerKeepsExistingPSKAndExtras(t *testing.T) {
	ctx := context.Background()
	f := awgtest.New()
	n, path, _ := newTestNode(t, f)
	// Меняем только адрес пира B, PSK в запросе не передаём.
	spec := awg.PeerSpec{PublicKey: awgtest.KeyB, AllowedIPs: []string{"10.20.0.30/32"}}
	if err := n.ApplyPeer(ctx, "awg-t0", spec); err != nil {
		t.Fatal(err)
	}
	body, _ := os.ReadFile(path)
	conf, _ := awg.Parse(body)
	p := conf.FindPeer(awgtest.KeyB)
	if p == nil || p.PresharedKey != awgtest.PSK {
		t.Fatalf("PSK из файла потерян: %+v", p)
	}
	if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.20.0.30/32" {
		t.Fatalf("адрес не обновлён: %+v", p)
	}
	if !f.Peers[awgtest.KeyB].HasPSK {
		t.Fatal("в рантайме PSK снят, хотя его не просили менять")
	}
}

func TestRemovePeer(t *testing.T) {
	ctx := context.Background()
	f := awgtest.New()
	n, path, _ := newTestNode(t, f)
	if err := n.RemovePeer(ctx, "awg-t0", awgtest.KeyA); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Peers[awgtest.KeyA]; ok {
		t.Fatal("пир остался в рантайме")
	}
	body, _ := os.ReadFile(path)
	if strings.Contains(string(body), awgtest.KeyA) {
		t.Fatal("пир остался в файле")
	}
	conf, _ := awg.Parse(body)
	if len(conf.Peers) != 1 {
		t.Fatalf("пиров в файле: %d", len(conf.Peers))
	}
}

func TestGuardBlocksWrites(t *testing.T) {
	ctx := context.Background()
	spec := awg.PeerSpec{PublicKey: awgtest.KeyC, AllowedIPs: []string{"10.20.0.9/32"}}

	t.Run("чужой менеджер активен", func(t *testing.T) {
		f := awgtest.New()
		f.Foreign = true
		n, path, _ := newTestNode(t, f)
		err := n.ApplyPeer(ctx, "awg-t0", spec)
		var ge *GuardError
		if !errors.As(err, &ge) || !strings.Contains(err.Error(), "wg-dashboard.service") {
			t.Fatalf("ожидалась охранная ошибка, получено: %v", err)
		}
		assertUntouched(t, path, f)
	})

	t.Run("чужая панель живёт в контейнере", func(t *testing.T) {
		f := awgtest.New()
		f.Containers = map[string]bool{"wg-easy": true}
		n, path, _ := newTestNode(t, f)
		n.ForeignManagers = []string{"docker:wg-easy"}
		err := n.ApplyPeer(ctx, "awg-t0", spec)
		var ge *GuardError
		if !errors.As(err, &ge) || !strings.Contains(err.Error(), "docker:wg-easy") {
			t.Fatalf("ожидалась охранная ошибка, получено: %v", err)
		}
		assertUntouched(t, path, f)
	})

	t.Run("контейнер остановлен — пишем", func(t *testing.T) {
		f := awgtest.New()
		f.Containers = map[string]bool{"wg-easy": false}
		n, _, _ := newTestNode(t, f)
		n.ForeignManagers = []string{"docker:wg-easy"}
		if err := n.ApplyPeer(ctx, "awg-t0", spec); err != nil {
			t.Fatalf("запись при остановленном контейнере: %v", err)
		}
		if _, ok := f.Peers[awgtest.KeyC]; !ok {
			t.Fatal("пир не поставлен")
		}
	})

	t.Run("контейнера нет вовсе — пишем", func(t *testing.T) {
		f := awgtest.New()
		n, _, _ := newTestNode(t, f)
		n.ForeignManagers = []string{"docker:wg-easy"}
		if err := n.ApplyPeer(ctx, "awg-t0", spec); err != nil {
			t.Fatalf("запись без контейнера: %v", err)
		}
		if _, ok := f.Peers[awgtest.KeyC]; !ok {
			t.Fatal("пир не поставлен")
		}
	})

	t.Run("SaveConfig в файле", func(t *testing.T) {
		f := awgtest.New()
		n, path, _ := newTestNode(t, f)
		body := strings.Replace(awgtest.ConfBody, "ListenPort = 443", "ListenPort = 443\nSaveConfig = true", 1)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		err := n.ApplyPeer(ctx, "awg-t0", spec)
		var ge *GuardError
		if !errors.As(err, &ge) || !strings.Contains(err.Error(), "SaveConfig") {
			t.Fatalf("ожидалась охранная ошибка, получено: %v", err)
		}
		if _, ok := f.Peers[awgtest.KeyC]; ok {
			t.Fatal("пир поставлен вопреки guard")
		}
	})

	t.Run("обфускация разошлась", func(t *testing.T) {
		f := awgtest.New()
		f.ObfRuntime = map[string]string{"Jc": "7"}
		n, path, _ := newTestNode(t, f)
		err := n.ApplyPeer(ctx, "awg-t0", spec)
		var ge *GuardError
		if !errors.As(err, &ge) || !strings.Contains(err.Error(), "обфускация") {
			t.Fatalf("ожидалась охранная ошибка, получено: %v", err)
		}
		assertUntouched(t, path, f)
	})
}

func assertUntouched(t *testing.T, path string, f *awgtest.Fake) {
	t.Helper()
	body, _ := os.ReadFile(path)
	if string(body) != awgtest.ConfBody {
		t.Fatal("файл изменён, хотя запись отклонена")
	}
	if len(f.SetCalls()) != 0 {
		t.Fatalf("были вызовы awg set: %v", f.SetCalls())
	}
}

func TestRuntimeFailureRollsBackFile(t *testing.T) {
	ctx := context.Background()
	f := awgtest.New()
	f.SetErr = errors.New("awg set: Operation not permitted")
	n, path, _ := newTestNode(t, f)
	err := n.ApplyPeer(ctx, "awg-t0", awg.PeerSpec{PublicKey: awgtest.KeyC, AllowedIPs: []string{"10.20.0.9/32"}})
	if err == nil {
		t.Fatal("ошибка рантайма не вернулась")
	}
	body, _ := os.ReadFile(path)
	if string(body) != awgtest.ConfBody {
		t.Fatalf("файл не откатился:\n%s", body)
	}
}

func TestReconcile(t *testing.T) {
	ctx := context.Background()
	f := awgtest.New()
	n, path, _ := newTestNode(t, f)
	before := ifaceSection(t, path)

	desired := []awg.PeerSpec{
		{PublicKey: awgtest.KeyA, AllowedIPs: []string{"10.20.0.2/32"}},                  // без изменений
		{PublicKey: awgtest.KeyB, AllowedIPs: []string{"10.20.0.33/32"}, ClearPSK: true}, // сменился адрес, PSK снимается
		{PublicKey: awgtest.KeyC, AllowedIPs: []string{"10.20.0.9/32"}, PresharedKey: awgtest.PSK},
	}
	res, err := n.Reconcile(ctx, "awg-t0", desired, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Added) != 1 || res.Added[0] != awgtest.KeyC {
		t.Fatalf("added = %v", res.Added)
	}
	if len(res.Updated) != 1 || res.Updated[0] != awgtest.KeyB {
		t.Fatalf("updated = %v", res.Updated)
	}
	if len(res.Untouched) != 1 || res.Untouched[0] != awgtest.KeyA {
		t.Fatalf("untouched = %v", res.Untouched)
	}
	if len(res.Removed) != 0 {
		t.Fatalf("removed = %v", res.Removed)
	}
	if f.Peers[awgtest.KeyB].HasPSK || f.Peers[awgtest.KeyB].Allowed != "10.20.0.33/32" {
		t.Fatalf("пир B в рантайме: %+v", f.Peers[awgtest.KeyB])
	}
	if got := ifaceSection(t, path); got != before {
		t.Fatal("секция [Interface] изменилась при reconcile")
	}
	body, _ := os.ReadFile(path)
	conf, _ := awg.Parse(body)
	if len(conf.Peers) != 3 {
		t.Fatalf("пиров в файле: %d", len(conf.Peers))
	}
	if p := conf.FindPeer(awgtest.KeyB); p == nil || p.PresharedKey != "" {
		t.Fatalf("PSK не снят в файле: %+v", p)
	}

	// Повторный прогон ничего не меняет.
	res2, err := n.Reconcile(ctx, "awg-t0", desired, false)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Changed() || len(res2.Untouched) != 3 {
		t.Fatalf("повторный reconcile: %+v", res2)
	}
}

func TestReconcileRemovesAndProtectsEmpty(t *testing.T) {
	ctx := context.Background()
	f := awgtest.New()
	n, path, _ := newTestNode(t, f)

	// Пустое желаемое состояние при непустом рантайме — отказ без флага.
	if _, err := n.Reconcile(ctx, "awg-t0", nil, false); err == nil {
		t.Fatal("пустой reconcile прошёл без allowEmpty")
	}
	if len(f.Peers) != 2 {
		t.Fatalf("пиры сняты вопреки защите: %+v", f.Peers)
	}

	res, err := n.Reconcile(ctx, "awg-t0", []awg.PeerSpec{{PublicKey: awgtest.KeyA, AllowedIPs: []string{"10.20.0.2/32"}}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 1 || res.Removed[0] != awgtest.KeyB {
		t.Fatalf("removed = %v", res.Removed)
	}
	if _, ok := f.Peers[awgtest.KeyB]; ok {
		t.Fatal("пир B остался в рантайме")
	}
	body, _ := os.ReadFile(path)
	if strings.Contains(string(body), awgtest.KeyB) {
		t.Fatal("пир B остался в файле")
	}

	// С флагом снимаются все.
	if _, err := n.Reconcile(ctx, "awg-t0", nil, true); err != nil {
		t.Fatal(err)
	}
	if len(f.Peers) != 0 {
		t.Fatalf("пиры остались: %+v", f.Peers)
	}
	body, _ = os.ReadFile(path)
	conf, _ := awg.Parse(body)
	if len(conf.Peers) != 0 {
		t.Fatalf("пиры остались в файле: %d", len(conf.Peers))
	}
	if got := ifaceSection(t, path); !strings.Contains(got, "PostUp = iptables") {
		t.Fatal("секция [Interface] пострадала")
	}
}

func TestBackupRotation(t *testing.T) {
	ctx := context.Background()
	f := awgtest.New()
	n, _, backupDir := newTestNode(t, f)
	for i := 0; i < awg.BackupsKept+3; i++ {
		spec := awg.PeerSpec{PublicKey: awgtest.KeyC, AllowedIPs: []string{fmt.Sprintf("10.20.0.%d/32", 100+i)}}
		if err := n.ApplyPeer(ctx, "awg-t0", spec); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != awg.BackupsKept {
		t.Fatalf("бэкапов: %d, ожидалось %d", len(entries), awg.BackupsKept)
	}
}
