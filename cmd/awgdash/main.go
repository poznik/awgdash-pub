// awgdash — панель управления AmneziaWG. Подкоманды: hub (по умолчанию), node, import, admin, mode, reconcile, doctor, version.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"filippo.io/age"

	"github.com/poznik/awgdash-pub/internal/awg"
	"github.com/poznik/awgdash-pub/internal/config"
	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/node"
	"github.com/poznik/awgdash-pub/internal/store"
	"github.com/poznik/awgdash-pub/internal/telegram"
	"github.com/poznik/awgdash-pub/internal/version"
	"github.com/poznik/awgdash-pub/internal/web"
)

func main() {
	envFile := flag.String("env", "", "файл KEY=VALUE для локального запуска (в systemd используется EnvironmentFile)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "awgdash %s\n\nиспользование: awgdash [-env файл] <команда>\n\n"+
			"  hub      хаб + локальный узел (по умолчанию)\n"+
			"  node     только узел (удалённый сервер, фаза 2)\n"+
			"  import   перенос пиров из чужой панели: awgdash import wgdashboard|wg-easy --interface <имя>\n"+
			"  backup   копии: backup now|list|verify|keygen\n"+
			"  restore  восстановление из копии: restore <файл.age>\n"+
			"  doctor   проверка окружения\n"+
			"  version  версия\n", version.Version)
	}
	flag.Parse()
	if *envFile != "" {
		if err := config.LoadEnvFile(*envFile); err != nil {
			fatal(err)
		}
	}
	// Пустая команда означает «роль из окружения»: юнит запускает бинарник без аргументов,
	// а AWGDASH_MODE решает, хаб это или узел.
	cmd, explicit := flag.Arg(0), flag.Arg(0) != ""
	if cmd == "" {
		cmd = "hub"
	}
	lvl := slog.LevelInfo
	if os.Getenv("AWGDASH_DEBUG") != "" {
		lvl = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))
	switch cmd {
	case "version":
		fmt.Println("awgdash", version.Version, "api", version.API)
	case "hub", "node":
		cfg, err := config.Load()
		if err != nil {
			fatal(err)
		}
		if explicit {
			cfg.Mode = cmd
		}
		if err := serve(cfg, log); err != nil {
			fatal(err)
		}
	case "import":
		cfg, err := config.Load()
		if err != nil {
			fatal(err)
		}
		os.Exit(importCmd(cfg, flag.Args()[1:]))
	case "admin":
		cfg, err := config.Load()
		if err != nil {
			fatal(err)
		}
		os.Exit(adminCmd(cfg, flag.Args()[1:]))
	case "seed":
		cfg, err := config.Load()
		if err != nil {
			fatal(err)
		}
		os.Exit(seedCmd(cfg, flag.Args()[1:]))
	case "purge":
		cfg, err := config.Load()
		if err != nil {
			fatal(err)
		}
		os.Exit(purgeCmd(cfg, flag.Args()[1:]))
	case "mode":
		cfg, err := config.Load()
		if err != nil {
			fatal(err)
		}
		os.Exit(modeCmd(cfg, flag.Args()[1:]))
	case "reconcile":
		cfg, err := config.Load()
		if err != nil {
			fatal(err)
		}
		os.Exit(reconcileCmd(cfg, flag.Args()[1:]))
	case "server":
		cfg, err := config.Load()
		if err != nil {
			fatal(err)
		}
		os.Exit(serverCmd(cfg, flag.Args()[1:]))
	case "backup":
		cfg, err := config.Load()
		if err != nil {
			fatal(err)
		}
		os.Exit(backupCmd(cfg, flag.Args()[1:]))
	case "restore":
		cfg, err := config.Load()
		if err != nil {
			fatal(err)
		}
		os.Exit(restoreCmd(cfg, flag.Args()[1:]))
	case "doctor":
		cfg, err := config.Load()
		if err != nil {
			fatal(err)
		}
		os.Exit(doctor(cfg))
	default:
		flag.Usage()
		os.Exit(2)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "awgdash:", err)
	os.Exit(1)
}

// newBot собирает оповещатель. Отдельно от serve, потому что разовым командам (копия по
// требованию) бот тоже нужен — но уже без цикла опроса.
func newBot(cfg *config.Config, st *store.Store, log *slog.Logger, rep telegram.Reporter) *telegram.Bot {
	tz, err := time.LoadLocation(cfg.TZ)
	if err != nil {
		tz = time.UTC
	}
	return telegram.New(telegram.NewClient(cfg.TelegramToken), st, log, rep, tz, cfg.TelegramAdminIDs)
}

func newNode(cfg *config.Config) *node.Node {
	n := node.New(cfg.AWGConfDir, cfg.AWGBin, awg.ExecRunner{Timeout: 10 * time.Second}, cfg.ForeignManagers)
	n.BackupDir = filepath.Join(cfg.DataDir, "conf-backup")
	return n
}

func serve(cfg *config.Config, log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	n := newNode(cfg)
	var hubStart func() error
	var stopped func() // прощальное сообщение боту: «панель остановлена» (FR-8.2)
	mux := http.NewServeMux()
	// Контракт узла /v1/* регистрируется только в режиме node. В режиме hub локальный узел
	// вызывается напрямую (LocalAgent → node.*), по сети хаб к себе не ходит, а открытый /v1/*
	// на слушателе админки — это доступ к записи пиров и к конфигу с приватным ключом сервера,
	// защищённый лишь общим паркобым токеном без ограничителя попыток. Обратный прокси
	// пропускал эти пути на публичное имя, поэтому в hub их просто нет (SPEC §9, FR-13.1).
	if cfg.Mode == "node" {
		api := &node.API{Node: n, Token: cfg.NodeToken}
		// Удалённый узел копит выборки сам: пока связь с хабом порвана, история не теряется
		// (SPEC FR-10.4). Хабу на своей машине буфер не нужен — он опрашивает интерфейсы напрямую.
		buf := node.NewBuffer()
		api.Samples = buf
		go n.RunSampler(ctx, buf, cfg.SampleEvery, log)
		api.Register(mux)
	}
	if cfg.Mode == "hub" {
		st, err := store.Open(cfg.DBPath)
		if err != nil {
			return fmt.Errorf("БД %s: %w", cfg.DBPath, err)
		}
		defer st.Close()
		h := hub.New(cfg, st, n, log)
		hubStart = func() error { return h.Start(ctx) }
		stopped = func() { h.NotifyStopped(log) }
		tz, err := time.LoadLocation(cfg.TZ)
		if err != nil {
			log.Warn("таймзона", "tz", cfg.TZ, "err", err)
			tz = time.UTC
		}
		w, err := web.New(h, tz, web.Options{AdminHost: cfg.AdminHost, PortalHost: cfg.PortalHost,
			SessionKey: []byte(cfg.SessionKey), ForwardedHops: cfg.ForwardedHops})
		if err != nil {
			return err
		}
		w.Register(mux)
		// Бот включается наличием токена: без него панель работает ровно так же, молча.
		if cfg.TelegramToken != "" {
			bot := newBot(cfg, st, log, h)
			h.Bot = bot
			go bot.Run(ctx)
		} else {
			log.Info("telegram: токен не задан, оповещатель выключен")
		}
	}
	srv := &http.Server{Addr: cfg.Listen, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", cfg.Listen)
	if err != nil {
		return err
	}
	log.Info("awgdash запущен", "mode", cfg.Mode, "listen", cfg.Listen, "version", version.Version, "conf_dir", cfg.AWGConfDir)
	if hubStart != nil {
		go func() {
			if err := hubStart(); err != nil {
				log.Error("старт хаба", "err", err)
				stop()
			}
		}()
	}
	go func() {
		<-ctx.Done()
		c, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		srv.Shutdown(c)
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	if stopped != nil {
		stopped()
	}
	log.Info("awgdash остановлен")
	return nil
}

// doctor — проверки окружения (SPEC FR-13.2). Возвращает код выхода: 0 — всё хорошо, 1 — есть проблемы.
func doctor(cfg *config.Config) int {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	n := newNode(cfg)
	problems := 0
	ok := func(format string, a ...any) { fmt.Printf("  ✓ "+format+"\n", a...) }
	bad := func(format string, a ...any) { problems++; fmt.Printf("  ✗ "+format+"\n", a...) }
	warn := func(format string, a ...any) { fmt.Printf("  ! "+format+"\n", a...) }

	fmt.Printf("awgdash %s · doctor\n", version.Version)
	if v, err := n.Tool.Version(ctx); err != nil {
		bad("awg (%s): %v", cfg.AWGBin, err)
	} else {
		ok("awg: %s", v)
		if !strings.Contains(v, "v3.") && !strings.Contains(v, "v4.") {
			warn("ожидалась ветка amneziawg-tools 3.x — формат dump может отличаться")
		}
	}
	if st, err := os.Stat(cfg.AWGConfDir); err != nil {
		bad("каталог конфигов %s: %v", cfg.AWGConfDir, err)
	} else if !st.IsDir() {
		bad("%s не каталог", cfg.AWGConfDir)
	} else {
		ok("каталог конфигов %s", cfg.AWGConfDir)
	}
	infos, err := n.Discover(ctx)
	if err != nil {
		bad("обнаружение интерфейсов: %v", err)
	}
	for _, i := range infos {
		ok("интерфейс %s: %s, udp/%d, MTU %d, пиров в файле %d, юнит %s", i.Name, i.Subnet, i.ListenPort, i.MTU, i.ConfPeers, map[bool]string{true: "активен", false: "НЕАКТИВЕН"}[i.UnitActive])
		if i.DumpError != "" {
			bad("  dump %s: %s (нужен CAP_NET_ADMIN и запущенный интерфейс)", i.Name, i.DumpError)
			continue
		}
		if !i.IsAWG {
			warn("  %s: рантайм без параметров AmneziaWG (чистый WireGuard?)", i.Name)
		}
		if i.SaveConfig {
			bad("  %s: SaveConfig=true — awg-quick down перепишет файл рантаймом; панель писать не будет", i.Name)
		}
		if res, err := n.Verify(ctx, i.Name); err != nil {
			bad("  verify %s: %v", i.Name, err)
		} else if res.OK {
			ok("  обфускация %s: %d/%d совпадают", i.Name, res.Matched, res.Total)
		} else {
			bad("  обфускация %s: %d/%d, расхождения: %v", i.Name, res.Matched, res.Total, res.Diffs)
		}
	}
	if fm := n.ForeignManagerActive(ctx); fm != "" {
		warn("активен чужой менеджер пиров %s — допустим только режим observe", fm)
	} else {
		ok("чужих менеджеров пиров не обнаружено (%s)", strings.Join(cfg.ForeignManagers, ", "))
	}
	if info, err := n.Metrics.Info(ctx); err != nil {
		warn("host info: %v", err)
	} else {
		ok("хост %s · %s · egress %s · %s", info.Hostname, info.Kernel, info.EgressIface, info.PublicIP)
	}
	if snap, err := n.Metrics.Snapshot(ctx); err == nil && snap.Supported {
		ok("метрики: диск %d/%d ГБ, RAM %d/%d МБ, load %.2f%s", snap.DiskUsed>>30, snap.DiskTotal>>30, snap.MemUsed>>20, snap.MemTotal>>20, snap.Load1, map[bool]string{true: ", reboot-required", false: ""}[snap.RebootRequired])
	}
	if cfg.Mode == "hub" {
		if f, err := os.OpenFile(cfg.DBPath, os.O_RDWR|os.O_CREATE, 0o600); err != nil {
			bad("БД %s: %v", cfg.DBPath, err)
		} else {
			f.Close()
			ok("БД %s доступна на запись", cfg.DBPath)
		}
	}
	if cfg.NodeToken == "" {
		warn("AWGDASH_NODE_TOKEN пуст — API узла будет отвечать 503")
	}
	// Telegram: проверяем не только токен, но и достижимость api.telegram.org — из России
	// она бывает недоступна, и молчащий бот выглядит как «панель сломалась».
	// Резервные копии: без публичного ключа age панель их не делает вовсе.
	if cfg.AgeRecipient == "" {
		warn("AWGDASH_AGE_RECIPIENT пуст — резервные копии выключены (awgdash backup keygen)")
	} else if _, err := age.ParseX25519Recipient(strings.TrimSpace(cfg.AgeRecipient)); err != nil {
		bad("AWGDASH_AGE_RECIPIENT: %v", err)
	} else {
		dir := filepath.Join(cfg.DataDir, "backups")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			bad("каталог копий %s: %v", dir, err)
		} else if entries, err := os.ReadDir(dir); err != nil {
			bad("каталог копий %s: %v", dir, err)
		} else {
			last := "копий пока нет"
			for _, e := range entries {
				if info, err := e.Info(); err == nil {
					last = e.Name() + " от " + info.ModTime().Format("02.01 15:04")
				}
			}
			ok("копии: ключ age на месте, %s", last)
		}
	}
	if cfg.EnvFile != "" {
		if _, err := os.Stat(cfg.EnvFile); err != nil {
			warn("%s недоступен — переменные окружения в копию не попадут: %v", cfg.EnvFile, err)
		}
	}
	if cfg.TelegramToken == "" {
		warn("AWGDASH_TELEGRAM_TOKEN пуст — оповещатель выключен")
	} else if me, err := telegram.NewClient(cfg.TelegramToken).GetMe(ctx); err != nil {
		bad("telegram: %v", err)
	} else {
		ok("telegram: бот @%s, получателей %d", me.Username, len(cfg.TelegramAdminIDs))
	}
	if cfg.Mode == "hub" {
		if st, err := store.Open(cfg.DBPath); err != nil {
			bad("администраторы: %v", err)
		} else {
			admins, err := st.Admins(ctx)
			switch {
			case err != nil:
				bad("администраторы: %v", err)
			case len(admins) == 0:
				bad("администраторов нет — войти некому: awgdash admin create <имя>")
			default:
				for _, a := range admins {
					if a.TOTPEnabled {
						ok("администратор %s, второй фактор включён", a.Username)
					} else {
						warn("администратор %s без второго фактора: awgdash admin totp %s", a.Username, a.Username)
					}
				}
			}
			// Версии узлов парка: проверки идут на узле его же кодом, поэтому отставший узел
			// ведёт себя иначе, чем хаб, — на живом парке из-за этого исправный интерфейс
			// показывался сломанным (FR-10.5).
			if servers, err := st.Servers(ctx); err == nil {
				stale := 0
				for _, srv := range servers {
					if srv.Local() || srv.Retired() || srv.AwgdashVersion == "" || srv.AwgdashVersion == version.Version {
						continue
					}
					warn("узел %s на версии %s, хаб на %s — обновите: make deploy HOST=%s", srv.Slug, srv.AwgdashVersion, version.Version, srv.Slug)
					stale++
				}
				if stale == 0 && len(servers) > 1 {
					ok("узлы парка на одной версии с хабом (%s)", version.Version)
				}
			}
			st.Close()
		}
		if cfg.SessionKey == "" {
			bad("AWGDASH_SESSION_KEY пуст — второй фактор работать не будет")
		}
		if cfg.AdminHost == "" {
			warn("AWGDASH_ADMIN_HOST пуст — Host не проверяется")
		} else {
			ok("админка отвечает только на Host %s (и на localhost)", cfg.AdminHost)
		}
		// Адрес клиента решает, кого блокировать за перебор и чей IP попадёт в журнал (FR-13.1b).
		if cfg.ForwardedHops == 0 {
			warn("AWGDASH_FORWARDED_HOPS=0 — адресом клиента считается RemoteAddr; за прокси все попытки входа окажутся в одном ведре")
		} else {
			ok("адрес клиента берётся из X-Forwarded-For, прокси перед панелью: %d", cfg.ForwardedHops)
		}
		ok("журналы хранятся %s", cfg.JournalRetention)
	}
	if problems == 0 {
		fmt.Println("всё в порядке")
		return 0
	}
	fmt.Printf("проблем: %d\n", problems)
	return 1
}
