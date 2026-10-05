package node

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/poznik/awgdash-pub/internal/awg"
	"github.com/poznik/awgdash-pub/internal/wgkey"
)

// Интеграционный прогон адаптера на настоящем интерфейсе AmneziaWG.
//
// Запускается только когда заданы переменные AWGDASH_IT_*; их печатает `deploy/awg-t0.sh up`.
// Обычный `go test ./...` этот тест пропускает — на машине разработчика интерфейса нет.
//
//	go test -c -o dist/node.test ./internal/node        (кросс-сборка под linux)
//	scp dist/node.test de:/tmp/ && ssh de 'sudo bash /tmp/awg-t0.sh up'
//	ssh de 'sudo env $(cat /run/awgdash-t0/env) /tmp/node.test -test.run TestIntegration -test.v'
func TestIntegrationRealInterface(t *testing.T) {
	iface := os.Getenv("AWGDASH_IT_IFACE")
	confDir := os.Getenv("AWGDASH_IT_CONF_DIR")
	awgBin := os.Getenv("AWGDASH_IT_AWG_BIN")
	if iface == "" || confDir == "" || awgBin == "" {
		t.Skip("нет AWGDASH_IT_IFACE/CONF_DIR/AWG_BIN — интеграционный прогон пропущен")
	}
	backupDir := os.Getenv("AWGDASH_IT_BACKUP_DIR")
	if backupDir == "" {
		backupDir = filepath.Join(confDir, "conf-backup")
	}
	ctx := context.Background()
	n := New(confDir, awgBin, awg.ExecRunner{Timeout: 10 * time.Second}, nil)
	n.BackupDir = backupDir
	confPath := filepath.Join(confDir, iface+".conf")

	before, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatal(err)
	}
	ifaceBefore := ifaceSectionOf(string(before))

	// 1. Интерфейс виден, обфускация файла и рантайма совпадает.
	info, err := n.Interface(ctx, iface)
	if err != nil {
		t.Fatal(err)
	}
	if info.DumpError != "" {
		t.Fatalf("dump: %s", info.DumpError)
	}
	if !info.IsAWG {
		t.Fatal("рантайм без параметров AmneziaWG — модуль amneziawg не тот?")
	}
	res, err := n.Verify(ctx, iface)
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK {
		t.Fatalf("обфускация: %d/%d, расхождения %v", res.Matched, res.Total, res.Diffs)
	}
	t.Logf("интерфейс %s: %s, порт %d, пиров в файле %d, обфускация %d/%d", iface, info.Subnet, info.ListenPort, info.ConfPeers, res.Matched, res.Total)

	// 2. Ставим новый пир: файл и рантайм.
	pair, err := wgkey.Generate()
	if err != nil {
		t.Fatal(err)
	}
	psk, err := wgkey.PSK()
	if err != nil {
		t.Fatal(err)
	}
	spec := awg.PeerSpec{PublicKey: pair.Public, PresharedKey: psk, AllowedIPs: []string{"10.77.0.77/32"}}
	if err := n.ApplyPeer(ctx, iface, spec); err != nil {
		t.Fatalf("ApplyPeer: %v", err)
	}
	_, peers, err := n.Dump(ctx, iface)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range peers {
		if p.PublicKey == pair.Public {
			found = true
			if !p.HasPSK {
				t.Fatal("PSK не доехал до рантайма")
			}
			if len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.77.0.77/32" {
				t.Fatalf("allowed-ips в рантайме: %v", p.AllowedIPs)
			}
		}
	}
	if !found {
		t.Fatal("новый пир не появился в рантайме")
	}
	body, _ := os.ReadFile(confPath)
	if ifaceSectionOf(string(body)) != ifaceBefore {
		t.Fatalf("секция [Interface] изменилась:\n--- было ---\n%s\n--- стало ---\n%s", ifaceBefore, ifaceSectionOf(string(body)))
	}
	conf, err := awg.Parse(body)
	if err != nil {
		t.Fatal(err)
	}
	if p := conf.FindPeer(pair.Public); p == nil || p.PresharedKey != psk {
		t.Fatalf("пир в файле: %+v", p)
	}
	// Сверка после записи обязана оставаться зелёной: awg set не трогает обфускацию.
	if res, err := n.Verify(ctx, iface); err != nil || !res.OK {
		t.Fatalf("verify после записи: %+v, err = %v", res, err)
	}

	// 3. Reconcile: приводим интерфейс к списку из двух пиров — третий уходит.
	keep := conf.Peers[0].PublicKey
	desired := []awg.PeerSpec{
		{PublicKey: keep, AllowedIPs: []string{"10.77.0.2/32"}},
		{PublicKey: pair.Public, PresharedKey: psk, AllowedIPs: []string{"10.77.0.78/32"}},
	}
	rec, err := n.Reconcile(ctx, iface, desired, false)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	t.Logf("reconcile: +%d ~%d -%d =%d", len(rec.Added), len(rec.Updated), len(rec.Removed), len(rec.Untouched))
	if len(rec.Removed) != 1 || len(rec.Updated) != 1 {
		t.Fatalf("reconcile: %+v", rec)
	}
	_, peers, _ = n.Dump(ctx, iface)
	if len(peers) != 2 {
		t.Fatalf("пиров в рантайме после reconcile: %d", len(peers))
	}
	for _, p := range peers {
		if p.PublicKey == pair.Public && (len(p.AllowedIPs) != 1 || p.AllowedIPs[0] != "10.77.0.78/32") {
			t.Fatalf("адрес не обновился: %v", p.AllowedIPs)
		}
	}

	// 4. Снимаем пир и возвращаем интерфейс к исходному состоянию.
	if err := n.RemovePeer(ctx, iface, pair.Public); err != nil {
		t.Fatalf("RemovePeer: %v", err)
	}
	_, peers, _ = n.Dump(ctx, iface)
	for _, p := range peers {
		if p.PublicKey == pair.Public {
			t.Fatal("пир остался в рантайме")
		}
	}
	body, _ = os.ReadFile(confPath)
	if strings.Contains(string(body), pair.Public) {
		t.Fatal("пир остался в файле")
	}

	// 5. Прошлые версии конфига сохранены.
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("каталог бэкапов: %v", err)
	}
	if len(entries) == 0 || len(entries) > awg.BackupsKept {
		t.Fatalf("бэкапов: %d", len(entries))
	}
	t.Logf("бэкапов конфига: %d", len(entries))

	// 6. Guard: пока чужой менеджер пиров активен, запись отклоняется.
	guarded := New(confDir, awgBin, awg.ExecRunner{Timeout: 10 * time.Second}, []string{"wg-dashboard.service"})
	guarded.BackupDir = backupDir
	if fm := guarded.ForeignManagerActive(ctx); fm == "" {
		t.Log("wg-dashboard.service неактивен — проверка guard пропущена")
	} else if err := guarded.ApplyPeer(ctx, iface, spec); err == nil {
		t.Fatalf("запись прошла, хотя %s активен", fm)
	} else {
		t.Logf("guard сработал: %v", err)
	}
}

func ifaceSectionOf(body string) string {
	if i := strings.Index(body, "\n[Peer]"); i >= 0 {
		return body[:i]
	}
	return body
}
