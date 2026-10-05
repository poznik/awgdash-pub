package hub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/poznik/awgdash-pub/internal/awgtest"
	"github.com/poznik/awgdash-pub/internal/backup"
	"github.com/poznik/awgdash-pub/internal/node"
	"github.com/poznik/awgdash-pub/internal/store"
)

// prepareBackup настраивает хаб на копии: временный каталог данных, свежая пара ключей age,
// файл .env рядом. Возвращает приватный ключ для проверки.
func prepareBackup(t *testing.T, h *Hub) []age.Identity {
	t.Helper()
	dir := t.TempDir()
	secret, public, err := backup.Keygen()
	if err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(dir, "awgdash.env")
	if err := os.WriteFile(envPath, []byte("AWGDASH_SESSION_KEY=секрет\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h.Cfg.DataDir = dir
	h.Cfg.AgeRecipient = public
	h.Cfg.EnvFile = envPath
	ids, err := age.ParseIdentities(strings.NewReader(secret))
	if err != nil {
		t.Fatal(err)
	}
	return ids
}

// Копия содержит базу, конфиг интерфейса и .env, а манифест описывает машину.
func TestBackupContainsStateAndConf(t *testing.T) {
	h, _, iface := testHub(t)
	ctx := context.Background()
	ids := prepareBackup(t, h)

	if _, _, err := h.Store.CreateUser(ctx, store.User{Name: "Аня"}); err != nil {
		t.Fatal(err)
	}
	path, size, err := h.Backup(ctx, backup.KindConfig)
	if err != nil {
		t.Fatal(err)
	}
	if size == 0 {
		t.Fatal("копия пустая")
	}
	out := filepath.Join(t.TempDir(), "unpacked")
	m, err := backup.Open(path, ids, out)
	if err != nil {
		t.Fatal(err)
	}
	if m.Kind != backup.KindConfig || m.Server.Slug != "de" {
		t.Fatalf("манифест: %+v", m)
	}
	if len(m.Interfaces) != 1 || m.Interfaces[0].Name != iface.Name {
		t.Fatalf("интерфейсы в манифесте: %+v", m.Interfaces)
	}
	// Конфиги раскладываются по серверам: в парке имена интерфейсов могут совпасть.
	for _, want := range []string{"db.sqlite", "conf/de/awg-t0.conf", "env/awgdash.env"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(want))); err != nil {
			t.Fatalf("в копии нет %s: %v", want, err)
		}
	}
	// Восстановленная база должна открываться и знать пользователя.
	st, err := store.Open(filepath.Join(out, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	u, err := st.UserByName(ctx, "Аня")
	if err != nil || u.Name != "Аня" {
		t.Fatalf("пользователь не восстановился: %+v, err = %v", u, err)
	}
}

// Конфигурационная копия не тащит наблюдение: история восстановима, а место она занимает.
func TestConfigBackupDropsHistory(t *testing.T) {
	h, _, _ := testHub(t)
	ctx := context.Background()
	ids := prepareBackup(t, h)
	if err := h.Store.InsertHostMetric(ctx, store.HostMetric{ServerID: h.ServerID, TS: time.Now(), CPU: 12}); err != nil {
		t.Fatal(err)
	}
	if err := h.Store.AddEvent(ctx, store.Event{Kind: "panel_started", ServerID: h.ServerID, Message: "старт"}); err != nil {
		t.Fatal(err)
	}
	path, _, err := h.Backup(ctx, backup.KindConfig)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "config")
	if _, err := backup.Open(path, ids, out); err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(out, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if n, err := st.CountEvents(ctx); err != nil || n != 0 {
		t.Fatalf("события остались в конфигурационной копии: %d (err %v)", n, err)
	}
	metrics, err := st.HostMetrics(ctx, h.ServerID, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(metrics) != 0 {
		t.Fatalf("метрики остались в конфигурационной копии: %d", len(metrics))
	}

	// Полная копия историю сохраняет.
	path, _, err = h.Backup(ctx, backup.KindFull)
	if err != nil {
		t.Fatal(err)
	}
	out = filepath.Join(t.TempDir(), "full")
	if _, err := backup.Open(path, ids, out); err != nil {
		t.Fatal(err)
	}
	full, err := store.Open(filepath.Join(out, "db.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer full.Close()
	if n, err := full.CountEvents(ctx); err != nil || n == 0 {
		t.Fatalf("полная копия потеряла события: %d (err %v)", n, err)
	}
}

// Без публичного ключа копия не делается — это защита, а не сбой конфигурации.
func TestBackupRefusesWithoutRecipient(t *testing.T) {
	h, _, _ := testHub(t)
	h.Cfg.DataDir = t.TempDir()
	h.Cfg.AgeRecipient = ""
	if _, _, err := h.Backup(context.Background(), backup.KindConfig); err != backup.ErrNoRecipient {
		t.Fatalf("ожидалась ErrNoRecipient, получено %v", err)
	}
}

// Локально держим 14 конфигурационных копий и 8 полных: старые уходят сами.
func TestPruneKeepsLimits(t *testing.T) {
	h, _, _ := testHub(t)
	h.Cfg.DataDir = t.TempDir()
	dir := h.BackupDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 1, 1, 3, 30, 0, 0, time.UTC)
	for i := 0; i < 20; i++ {
		name := backup.Name(backup.KindConfig, base.AddDate(0, 0, i))
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 12; i++ {
		name := backup.Name(backup.KindFull, base.AddDate(0, 0, 7*i))
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.pruneBackups(); err != nil {
		t.Fatal(err)
	}
	files, err := h.Backups()
	if err != nil {
		t.Fatal(err)
	}
	var config, full int
	for _, f := range files {
		if strings.HasPrefix(f.Name, "awgdash-config-") {
			config++
		}
		if strings.HasPrefix(f.Name, "awgdash-full-") {
			full++
		}
	}
	if config != keepConfig || full != keepFull {
		t.Fatalf("осталось config=%d full=%d, ожидалось %d и %d", config, full, keepConfig, keepFull)
	}
	// Уходят именно старые: свежая копия должна остаться.
	newest := backup.Name(backup.KindConfig, base.AddDate(0, 0, 19))
	if _, err := os.Stat(filepath.Join(dir, newest)); err != nil {
		t.Fatalf("удалена свежая копия %s", newest)
	}
}

// Копия парка обязана содержать конфиги удалённых узлов. Разовая команда CLI держит реестр
// пустым, пока его не наполнят: без этого `backup now --full` молча складывал конфиги только
// локального сервера, а kz и hel пропускал с предупреждением «сервер N не зарегистрирован».
func TestBackupIncludesRemoteNodeConf(t *testing.T) {
	h, _, _ := testHub(t)
	ctx := context.Background()
	ids := prepareBackup(t, h)
	h.Cfg.NodeToken = "секрет"

	// Узел «kz» — настоящий API узла на локальном порту, как он виден хабу через ssh-туннель.
	dir := t.TempDir()
	confDir := filepath.Join(dir, "etc")
	if _, err := awgtest.WriteConf(confDir, "awg-kz"); err != nil {
		t.Fatal(err)
	}
	n := node.New(confDir, "awg", awgtest.New(), nil)
	n.BackupDir = filepath.Join(dir, "conf-backup")
	mux := http.NewServeMux()
	(&node.API{Node: n, Token: "секрет"}).Register(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	port, err := strconv.Atoi(srv.URL[strings.LastIndex(srv.URL, ":")+1:])
	if err != nil {
		t.Fatal(err)
	}

	kz, err := h.Store.AddServer(ctx, store.NewServer{Slug: "kz", Title: "Казахстан", NodePort: port})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.Store.UpsertInterface(ctx, kz.ID, "awg-kz", store.InterfaceFacts{
		ConfPath: filepath.Join(confDir, "awg-kz.conf"), Subnet: "10.30.0.0/24", ServerAddress: "10.30.0.1/24",
		ListenPort: 443, MTU: 1280, IsAWG: true,
	}); err != nil {
		t.Fatal(err)
	}

	// Пока реестр не наполнен, узел хабу неизвестен и его конфиг в копию не попадает.
	path, _, err := h.Backup(ctx, backup.KindFull)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "before")
	if _, err := backup.Open(path, ids, out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, filepath.FromSlash("conf/kz/awg-kz.conf"))); err == nil {
		t.Fatal("конфиг чужого узла попал в копию до того, как реестр наполнили — тест ничего не проверяет")
	}

	if err := h.LoadServers(ctx); err != nil {
		t.Fatal(err)
	}
	// В реестре после наполнения обязаны быть оба узла: локальный тоже, иначе разовая команда
	// печатает состав парка без самой машины, на которой работает.
	var slugs []string
	for _, srv := range h.Servers() {
		slugs = append(slugs, srv.Slug)
	}
	sort.Strings(slugs)
	if len(slugs) != 2 || slugs[0] != "de" || slugs[1] != "kz" {
		t.Fatalf("парк в реестре: %v", slugs)
	}
	path, _, err = h.Backup(ctx, backup.KindFull)
	if err != nil {
		t.Fatal(err)
	}
	out = filepath.Join(t.TempDir(), "after")
	m, err := backup.Open(path, ids, out)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"conf/de/awg-t0.conf", "conf/kz/awg-kz.conf"} {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(want))); err != nil {
			t.Fatalf("в копии парка нет %s: %v", want, err)
		}
	}
	var names []string
	for _, i := range m.Interfaces {
		names = append(names, i.Name)
	}
	if len(m.Interfaces) != 2 {
		t.Fatalf("манифест обязан описывать оба интерфейса, а описывает %v", names)
	}
}
