package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"time"

	"github.com/poznik/awgdash-pub/internal/config"
	"github.com/poznik/awgdash-pub/internal/hub"
	"github.com/poznik/awgdash-pub/internal/store"
)

// modeCmd — `awgdash mode --interface <имя> [--set own|observe]` (FR-1.2).
// Без --set печатает предпроверки; с --set переключает режим, если они зелёные.
func modeCmd(cfg *config.Config, args []string) int {
	fs := flag.NewFlagSet("mode", flag.ContinueOnError)
	iface := fs.String("interface", "", "имя интерфейса")
	set := fs.String("set", "", "own | observe — переключить режим")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *iface == "" {
		fmt.Fprintln(os.Stderr, "использование: awgdash mode --interface <имя> [--set own|observe]")
		return 2
	}
	if *set != "" && *set != hub.ModeOwn && *set != "observe" {
		fmt.Fprintf(os.Stderr, "awgdash: --set ожидает own или observe, получено %q\n", *set)
		return 2
	}
	return withHub(cfg, func(ctx context.Context, h *hub.Hub, st *store.Store) int {
		target, err := findInterface(ctx, st, *iface)
		if err != nil {
			fmt.Fprintln(os.Stderr, "awgdash:", err)
			return 1
		}
		rd, err := h.ModeReadiness(ctx, target.ID, true)
		if err != nil {
			fmt.Fprintln(os.Stderr, "awgdash:", err)
			return 1
		}
		printReadiness(rd)
		if *set == "" {
			return 0
		}
		rd, err = h.SwitchInterfaceMode(ctx, target.ID, *set, store.ActorAdmin, "cli")
		if err != nil {
			fmt.Fprintln(os.Stderr, "awgdash:", err)
			return 1
		}
		fmt.Printf("режим интерфейса %s: %s\n", rd.Interface, rd.Mode)
		return 0
	})
}

func printReadiness(rd hub.ModeReadiness) {
	fmt.Printf("интерфейс %s · режим %s\n", rd.Interface, rd.Mode)
	for _, c := range rd.Checks {
		mark := "✗"
		if c.OK {
			mark = "✓"
		}
		note := ""
		if c.Note != "" {
			note = " — " + c.Note
		}
		fmt.Printf("  %s %s%s\n", mark, c.Title, note)
	}
	for _, u := range rd.Unassigned {
		fmt.Printf("      нераспределённый пир: %s\n", u)
	}
	if rd.Ready {
		fmt.Println("готов к режиму own")
	}
}

// reconcileCmd — `awgdash reconcile --interface <имя> [--dry-run]`: привести интерфейс к БД (SPEC §4.3).
func reconcileCmd(cfg *config.Config, args []string) int {
	fs := flag.NewFlagSet("reconcile", flag.ContinueOnError)
	iface := fs.String("interface", "", "имя интерфейса")
	dry := fs.Bool("dry-run", false, "показать разницу и ничего не менять")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *iface == "" {
		fmt.Fprintln(os.Stderr, "использование: awgdash reconcile --interface <имя> [--dry-run]")
		return 2
	}
	return withHub(cfg, func(ctx context.Context, h *hub.Hub, st *store.Store) int {
		target, err := findInterface(ctx, st, *iface)
		if err != nil {
			fmt.Fprintln(os.Stderr, "awgdash:", err)
			return 1
		}
		if *dry {
			res, err := h.PlanReconcile(ctx, target.ID)
			if err != nil {
				fmt.Fprintln(os.Stderr, "awgdash:", err)
				return 1
			}
			fmt.Printf("примерка reconcile %s: поставить %d, обновить %d, снять %d, без изменений %d\n",
				target.Name, len(res.Added), len(res.Updated), len(res.Removed), len(res.Untouched))
			printKeys("  поставить", res.Added)
			printKeys("  обновить", res.Updated)
			printKeys("  снять", res.Removed)
			return 0
		}
		res, err := h.ReconcileInterface(ctx, target.ID, store.ActorAdmin, "cli")
		if err != nil {
			fmt.Fprintln(os.Stderr, "awgdash:", err)
			return 1
		}
		fmt.Printf("reconcile %s: поставлено %d, обновлено %d, снято %d, без изменений %d\n",
			target.Name, len(res.Added), len(res.Updated), len(res.Removed), len(res.Untouched))
		return 0
	})
}

func printKeys(title string, keys []string) {
	for _, k := range keys {
		fmt.Printf("%s: %s\n", title, k)
	}
}

// withHub открывает БД и собирает хаб без фоновых циклов — для разовых команд CLI.
func withHub(cfg *config.Config, fn func(context.Context, *hub.Hub, *store.Store) int) int {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "awgdash: БД %s: %v\n", cfg.DBPath, err)
		return 1
	}
	defer st.Close()
	h := hub.New(cfg, st, newNode(cfg), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if id, err := st.UpsertLocalServer(ctx, cfg.ServerSlug, cfg.ServerTitle); err == nil {
		h.ServerID = id
	}
	// Реестр удалённых узлов наполняется только в работающем хабе, а разовым командам он нужен
	// не меньше: без него `mode` и `reconcile` для чужого сервера падают с «сервер N не
	// зарегистрирован», хотя он в панели есть — просто клиент к нему не создан.
	if err := h.LoadServers(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "awgdash: реестр серверов:", err)
	}
	return fn(ctx, h, st)
}
