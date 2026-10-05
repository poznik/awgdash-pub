package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/backup"
	"github.com/poznik/awgdash-pub/internal/config"
	"github.com/poznik/awgdash-pub/internal/node"
)

// restoreCmd — `awgdash restore <файл.age>` (SPEC FR-9.5). Единственное место, где панель
// трогает юнит интерфейса, и только по явному подтверждению оператора.
//
// Команда запускается от root на чистом сервере: она пишет конфиг интерфейса (root:0600),
// .env хаба и базу панели, после чего предлагает поднять интерфейс и сверяет обфускацию.
func restoreCmd(cfg *config.Config, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, `awgdash restore <файл.age> [--age-key <файл|->] [--dry-run] [--yes] [--no-start] [--owner <пользователь>]

  --age-key   приватный ключ age; по умолчанию читается со stdin
  --dry-run   показать план и выйти, ничего не записывая
  --yes       не спрашивать подтверждений (для неинтерактивного запуска)
  --no-start  не поднимать интерфейс после восстановления
  --drill     учебное восстановление рядом с живой панелью: токен бота из .env вычищается,
              интерфейс не поднимается (иначе два бота дерутся за один long polling)
  --server    восстанавливать конфиги только этого сервера парка (слаг из манифеста)
  --owner     кому отдать базу панели (по умолчанию awgdash)`)
		return 2
	}
	src := args[0]
	keyPath, owner, onlyServer := "-", "awgdash", ""
	dryRun, assumeYes, noStart, drill := false, false, false, false
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "--age-key":
			if i+1 < len(args) {
				keyPath = args[i+1]
				i++
			}
		case "--owner":
			if i+1 < len(args) {
				owner = args[i+1]
				i++
			}
		case "--server":
			if i+1 < len(args) {
				onlyServer = args[i+1]
				i++
			}
		case "--dry-run":
			dryRun = true
		case "--yes":
			assumeYes = true
		case "--no-start":
			noStart = true
		case "--drill":
			drill, noStart = true, true
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	ids, err := backup.Identities(keyPath)
	if err != nil {
		return fail(err)
	}
	dir, err := os.MkdirTemp("", "awgdash-restore-")
	if err != nil {
		return fail(err)
	}
	defer os.RemoveAll(dir)

	m, err := backup.Open(src, ids, dir)
	if err != nil {
		return fail(err)
	}
	printManifest(m)

	n := newNode(cfg)
	fmt.Println("\nсверка с этой машиной:")
	info, err := n.Metrics.Info(ctx)
	if err != nil {
		fmt.Printf("  ! сведения о хосте недоступны: %v\n", err)
	}
	if v, err := n.Tool.Version(ctx); err != nil {
		fmt.Printf("  ! awg не найден: %v — интерфейс поднять не получится\n", err)
	} else if v != m.AWGVersion && m.AWGVersion != "" {
		fmt.Printf("  ! awg здесь %s, в копии %s — форматы конфига совместимы, но проверьте обфускацию после запуска\n", v, m.AWGVersion)
	} else {
		fmt.Printf("  ✓ awg %s\n", v)
	}
	// Egress-интерфейс входит в PostUp/PostDown правилами маскарада: на новой машине он
	// обычно называется иначе, и без правки NAT молча не заработает.
	rewriteEgress := ""
	if info.EgressIface != "" && m.Server.EgressIface != "" && info.EgressIface != m.Server.EgressIface {
		fmt.Printf("  ! egress здесь %s, в копии %s — правила NAT будут переписаны\n", info.EgressIface, m.Server.EgressIface)
		rewriteEgress = info.EgressIface
	} else if info.EgressIface != "" {
		fmt.Printf("  ✓ egress %s\n", info.EgressIface)
	}

	if onlyServer != "" {
		// Копия хранит конфиги всего парка; на конкретной машине нужен только её узел.
		m = onlyOf(m, onlyServer)
		if len(m.Interfaces) == 0 {
			return fail(fmt.Errorf("в копии нет интерфейсов сервера %q", onlyServer))
		}
		fmt.Printf("\nвосстанавливаем только сервер %s\n", onlyServer)
	}
	plan := restorePlan(cfg, dir, m)
	fmt.Println("\nбудет записано:")
	for _, p := range plan {
		fmt.Printf("  %s → %s (%s)\n", p.label, p.to, p.what)
	}
	if dryRun {
		fmt.Println("\n--dry-run: ничего не записано")
		return 0
	}
	if !assumeYes && !confirm("Записать перечисленное?") {
		fmt.Println("отменено")
		return 1
	}

	for _, p := range plan {
		if err := installFile(p, m, rewriteEgress, owner); err != nil {
			return fail(err)
		}
		fmt.Printf("  ✓ %s\n", p.to)
	}
	if drill {
		// Учебное восстановление: бот остаётся у боевой панели. Два процесса с одним токеном
		// отбирают друг у друга обновления, и оповещения начинают теряться.
		if err := muteBot(cfg.EnvFile); err != nil {
			fmt.Printf("  ! не удалось убрать токен бота из %s: %v\n", cfg.EnvFile, err)
		} else {
			fmt.Printf("  ✓ %s: токен бота вычищен (учебное восстановление)\n", cfg.EnvFile)
		}
	}

	if noStart {
		if drill {
			fmt.Println("\nучебное восстановление: интерфейс не поднимался, бот выключен.")
			fmt.Println("Поднять вручную (если порт занят — сперва смените ListenPort): systemctl start awg-quick@<имя>")
		} else {
			fmt.Println("\nинтерфейс не поднимался (--no-start). Дальше: systemctl enable --now awg-quick@<имя>")
		}
		return 0
	}
	for _, i := range m.Interfaces {
		if !assumeYes && !confirm(fmt.Sprintf("Поднять интерфейс %s (systemctl enable --now awg-quick@%s)?", i.Name, i.Name)) {
			fmt.Println("  интерфейс", i.Name, "оставлен выключенным")
			continue
		}
		if err := startInterface(ctx, i.Name); err != nil {
			fmt.Printf("  ✗ %s: %v\n", i.Name, err)
			continue
		}
		fmt.Printf("  ✓ %s поднят\n", i.Name)
		verifyInterface(ctx, n, i.Name)
	}
	fmt.Println("\nдальше вручную: правила ufw (порты интерфейсов), systemctl enable --now awgdash, awgdash doctor")
	return 0
}

// planItem — один файл восстановления: откуда во временном каталоге, куда на машине и
// с какими правами.
type planItem struct {
	src, label, to, what string
	mode                 os.FileMode
	owner                string // "root" или пользователь панели
}

func restorePlan(cfg *config.Config, dir string, m backup.Manifest) []planItem {
	var out []planItem
	for _, i := range m.Interfaces {
		// Копии парка складывают конфиги по серверам (conf/<слаг>/awg-x.conf); в копиях
		// одиночной панели путь плоский — принимаем оба.
		src := filepath.Join(dir, "conf", i.Server, filepath.Base(i.ConfPath))
		if _, err := os.Stat(src); err != nil {
			src = filepath.Join(dir, "conf", filepath.Base(i.ConfPath))
			if _, err := os.Stat(src); err != nil {
				continue
			}
		}
		out = append(out, planItem{src: src, label: "conf/" + filepath.Base(src), to: confTarget(cfg.AWGConfDir, i.Name),
			what: "конфиг интерфейса, root:0600", mode: 0o600, owner: "root"})
	}
	if envs, _ := filepath.Glob(filepath.Join(dir, "env", "*")); len(envs) > 0 {
		out = append(out, planItem{src: envs[0], label: "env/" + filepath.Base(envs[0]), to: cfg.EnvFile,
			what: "переменные окружения, root:0600", mode: 0o600, owner: "root"})
	}
	out = append(out, planItem{src: filepath.Join(dir, "db.sqlite"), label: "db.sqlite", to: cfg.DBPath,
		what: "база панели", mode: 0o600, owner: "panel"})
	return out
}

// installFile кладёт файл на место с нужными правами. Конфиг интерфейса по пути правится:
// имя egress-интерфейса на новой машине другое.
func installFile(p planItem, m backup.Manifest, rewriteEgress, owner string) error {
	dir := filepath.Dir(p.to)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	body, err := os.ReadFile(p.src)
	if err != nil {
		return err
	}
	if rewriteEgress != "" && strings.HasSuffix(p.to, ".conf") {
		body = []byte(strings.ReplaceAll(string(body), "-o "+m.Server.EgressIface, "-o "+rewriteEgress))
	}
	// Существующий файл сохраняем: восстановление поверх живой машины должно быть обратимо.
	if _, err := os.Stat(p.to); err == nil {
		if err := os.Rename(p.to, p.to+".before-restore"); err != nil {
			return err
		}
	}
	if err := os.WriteFile(p.to, body, p.mode); err != nil {
		return err
	}
	if p.owner == "panel" && owner != "" {
		if out, err := exec.Command("chown", owner+":"+owner, p.to).CombinedOutput(); err != nil {
			return fmt.Errorf("chown %s: %v: %s", p.to, err, strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func startInterface(ctx context.Context, name string) error {
	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(c, "systemctl", "enable", "--now", "awg-quick@"+name).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func verifyInterface(ctx context.Context, n *node.Node, name string) {
	res, err := n.Verify(ctx, name)
	if err != nil {
		fmt.Printf("    ! сверка обфускации: %v\n", err)
		return
	}
	if res.OK {
		fmt.Printf("    ✓ обфускация %d/%d\n", res.Matched, res.Total)
		return
	}
	fmt.Printf("    ✗ обфускация %d/%d, расхождения: %v\n", res.Matched, res.Total, res.Diffs)
}

func confirm(question string) bool {
	fmt.Printf("%s [y/N]: ", question)
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes" || answer == "да"
}

// muteBot убирает токен Telegram из восстановленного .env: на учебном сервере оповещатель
// должен молчать, иначе он перехватит long polling у боевой панели.
func muteBot(envPath string) error {
	body, err := os.ReadFile(envPath)
	if err != nil {
		return err
	}
	var out []string
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "AWGDASH_TELEGRAM_TOKEN=") {
			out = append(out, "AWGDASH_TELEGRAM_TOKEN=")
			continue
		}
		out = append(out, line)
	}
	return os.WriteFile(envPath, []byte(strings.Join(out, "\n")), 0o600)
}

// onlyOf оставляет в манифесте интерфейсы одного сервера парка: при переезде одного узла
// чужие конфиги на эту машину класть незачем.
func onlyOf(m backup.Manifest, slug string) backup.Manifest {
	var kept []backup.Iface
	for _, i := range m.Interfaces {
		if strings.EqualFold(i.Server, slug) {
			kept = append(kept, i)
		}
	}
	m.Interfaces = kept
	return m
}
