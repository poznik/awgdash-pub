package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/backup"
	"github.com/poznik/awgdash-pub/internal/config"
	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/humanize"
	"github.com/poznik/awgdash-pub/internal/store"
)

// backupCmd — `awgdash backup now|list|verify|keygen` (SPEC FR-13.2, §6.9).
func backupCmd(cfg *config.Config, args []string) int {
	if len(args) == 0 {
		backupUsage()
		return 2
	}
	switch args[0] {
	case "now":
		return backupNow(cfg, args[1:])
	case "list":
		return backupList(cfg)
	case "verify":
		return backupVerify(args[1:])
	case "keygen":
		return backupKeygen(cfg, args[1:])
	default:
		backupUsage()
		return 2
	}
}

func backupUsage() {
	fmt.Fprintln(os.Stderr, `awgdash backup — резервные копии

  awgdash backup now [--full]        снять копию сейчас и разослать её
  awgdash backup list                локальные копии
  awgdash backup verify <файл.age> [--age-key <файл|->]
                                     расшифровать и проверить целостность, ничего не применяя
  awgdash backup keygen [--install]  новая пара ключей age: приватный — в менеджер паролей,
                                     --install сразу дописывает публичный в .env (нужен root)`)
}

// backupNow снимает копию тем же путём, что и расписание: те же файлы, та же рассылка.
func backupNow(cfg *config.Config, args []string) int {
	kind := backup.KindConfig
	for _, a := range args {
		if a == "--full" {
			kind = backup.KindFull
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	h, closeHub, err := openHub(cfg)
	if err != nil {
		return fail(err)
	}
	defer closeHub()
	// Реестр удалённых узлов наполняется только в работающем хабе, а копия обязана нести конфиги
	// всего парка: без этого разовая команда складывала конфиг локального сервера, а остальные
	// пропускала с предупреждением «сервер N не зарегистрирован в панели».
	if err := h.LoadServers(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "awgdash: реестр серверов:", err)
	}
	slugs := make([]string, 0, len(h.Servers()))
	for _, srv := range h.Servers() {
		slugs = append(slugs, srv.Slug)
	}
	sort.Strings(slugs)
	fmt.Println("парк:", strings.Join(slugs, ", "))
	path, err := h.RunBackup(ctx, kind)
	if err != nil {
		return fail(err)
	}
	st, _ := os.Stat(path)
	fmt.Printf("копия готова: %s (%s)\n", path, humanize.Bytes(uint64(st.Size())))
	if h.Bot == nil {
		fmt.Println("бот не настроен — копия осталась только на сервере")
	}
	return 0
}

func backupList(cfg *config.Config) int {
	h, closeHub, err := openHub(cfg)
	if err != nil {
		return fail(err)
	}
	defer closeHub()
	files, err := h.Backups()
	if err != nil {
		return fail(err)
	}
	if len(files) == 0 {
		fmt.Println("копий пока нет:", h.BackupDir())
		return 0
	}
	for _, f := range files {
		fmt.Printf("%-44s %10s  %s\n", f.Name, humanize.Bytes(uint64(f.Size)), f.At.Format("02.01.2006 15:04"))
	}
	return 0
}

// backupVerify проверяет копию, ничего не применяя (FR-9.7): расшифровка, контрольные суммы,
// печать манифеста.
func backupVerify(args []string) int {
	if len(args) == 0 {
		backupUsage()
		return 2
	}
	src := args[0]
	keyPath := "-"
	for i := 1; i < len(args); i++ {
		if args[i] == "--age-key" && i+1 < len(args) {
			keyPath = args[i+1]
		}
	}
	if keyPath == "-" {
		fmt.Fprintln(os.Stderr, "приватный ключ age ожидается на stdin (или --age-key <файл>)")
	}
	ids, err := backup.Identities(keyPath)
	if err != nil {
		return fail(err)
	}
	m, err := backup.Open(src, ids, "")
	if err != nil {
		return fail(err)
	}
	printManifest(m)
	fmt.Println("\nцелостность: все файлы на месте, контрольные суммы сходятся")
	return 0
}

func printManifest(m backup.Manifest) {
	fmt.Printf("копия %s от %s\n", m.Kind, m.CreatedAt.Format("02.01.2006 15:04"))
	fmt.Printf("  панель %s · схема %s · awg %s\n", m.Version, m.Schema, m.AWGVersion)
	fmt.Printf("  сервер %s (%s) · адрес %s · egress %s\n", m.Server.Slug, m.Server.Hostname, m.Server.PublicIP, m.Server.EgressIface)
	for _, i := range m.Interfaces {
		fmt.Printf("  интерфейс %s · %s · udp/%d · MTU %d · режим %s · пиров %d · обфускация %d\n",
			i.Name, i.Subnet, i.ListenPort, i.MTU, i.Mode, i.Peers, i.Obfuscation)
	}
	for _, f := range m.Files {
		fmt.Printf("  %-28s %8s  %s\n", f.Name, humanize.Bytes(uint64(f.Size)), f.SHA256[:12])
	}
}

// backupKeygen печатает новую пару ключей. Приватный виден один раз: панель его не хранит
// и восстановить не может. С --install публичный ключ сразу прописывается в .env.
func backupKeygen(cfg *config.Config, args []string) int {
	install := false
	for _, a := range args {
		if a == "--install" {
			install = true
		}
	}
	secret, public, err := backup.Keygen()
	if err != nil {
		return fail(err)
	}
	fmt.Println("# приватный ключ — в менеджер паролей; на сервере его быть не должно,")
	fmt.Println("# без него зашифрованную копию не открыть никому, включая панель")
	fmt.Println(secret)
	fmt.Println()
	if !install {
		fmt.Println("# публичный ключ — в " + cfg.EnvFile)
		fmt.Println("AWGDASH_AGE_RECIPIENT=" + public)
		return 0
	}
	if err := installRecipient(cfg.EnvFile, public); err != nil {
		return fail(err)
	}
	fmt.Printf("публичный ключ записан в %s: %s\n", cfg.EnvFile, public)
	fmt.Println("перезапустите панель, чтобы она его увидела: systemctl restart awgdash")
	return 0
}

// installRecipient дописывает публичный ключ в .env, заменяя прежнюю строку. Файл с секретами
// переписывается целиком через временный: оборванная запись оставила бы панель без токенов.
func installRecipient(envPath, public string) error {
	body, err := os.ReadFile(envPath)
	if err != nil {
		return err
	}
	var lines []string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "AWGDASH_AGE_RECIPIENT=") {
			continue
		}
		lines = append(lines, line)
	}
	for len(lines) > 0 && strings.TrimSpace(lines[len(lines)-1]) == "" {
		lines = lines[:len(lines)-1]
	}
	lines = append(lines, "AWGDASH_AGE_RECIPIENT="+public, "")
	tmp := envPath + ".new"
	if err := os.WriteFile(tmp, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, envPath)
}

// openHub поднимает хаб без веб-сервера и фоновых циклов: разовым командам нужен только
// доступ к БД, узлу и настройкам.
func openHub(cfg *config.Config) (*hub.Hub, func(), error) {
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return nil, nil, fmt.Errorf("БД %s: %w", cfg.DBPath, err)
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	h := hub.New(cfg, st, newNode(cfg), log)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	id, err := st.UpsertLocalServer(ctx, cfg.ServerSlug, cfg.ServerTitle)
	if err != nil {
		st.Close()
		return nil, nil, err
	}
	h.ServerID = id
	// Бот нужен, чтобы копия ушла в личку: цикл опроса при этом не запускается.
	if cfg.TelegramToken != "" {
		h.Bot = newBot(cfg, st, log, h)
	}
	return h, func() { st.Close() }, nil
}

// confTarget — куда лечь конфигу интерфейса из архива.
func confTarget(confDir, name string) string {
	return filepath.Join(confDir, strings.TrimSuffix(filepath.Base(name), ".conf")+".conf")
}
