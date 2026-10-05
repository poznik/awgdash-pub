package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/poznik/awgdash-pub/internal/config"
	"github.com/poznik/awgdash-pub/internal/importer"
	"github.com/poznik/awgdash-pub/internal/store"
)

// importCmd — `awgdash import wgdashboard|wg-easy --db … --interface …` (FR-11.1).
// Импорт только наполняет БД хаба: интерфейс не трогается ни в каком режиме.
func importCmd(cfg *config.Config, args []string) int {
	source := ""
	if len(args) > 0 {
		source = args[0]
	}
	if source != "wgdashboard" && source != "wg-easy" {
		fmt.Fprintln(os.Stderr, "использование: awgdash import wgdashboard --db <wgdashboard.db> --interface <имя> [--user <имя>] [--dry-run]")
		fmt.Fprintln(os.Stderr, "               awgdash import wg-easy --db <wg-easy.db> --interface <имя> [--source <имя в базе>] [--user <имя>] [--dry-run]")
		return 2
	}
	fs := flag.NewFlagSet("import "+source, flag.ContinueOnError)
	defDB := "/opt/WGDashboard/src/db/wgdashboard.db"
	if source == "wg-easy" {
		defDB = "/var/lib/docker/volumes/wg-easy_etc_wireguard/_data/wg-easy.db"
	}
	dbPath := fs.String("db", defDB, "база чужой панели (открывается только на чтение)")
	iface := fs.String("interface", "", "интерфейс панели, которому принадлежат пиры")
	srcIface := fs.String("source", "", "имя интерфейса в базе источника (wg-easy: обычно wg0; пусто — единственный)")
	owner := fs.String("user", "", "кому назначить устройства (wgdashboard: по умолчанию «"+importer.UnassignedUser+"»; wg-easy: владелец берётся из имени устройства)")
	dry := fs.Bool("dry-run", false, "показать, что будет сделано, и ничего не записывать")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *iface == "" {
		fmt.Fprintln(os.Stderr, "awgdash: не задан --interface")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	st, err := store.Open(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "awgdash: БД %s: %v\n", cfg.DBPath, err)
		return 1
	}
	defer st.Close()

	target, err := findInterface(ctx, st, *iface)
	if err != nil {
		fmt.Fprintln(os.Stderr, "awgdash:", err)
		return 1
	}
	var rep importer.Report
	if source == "wg-easy" {
		rep, err = importer.WGEasy(ctx, st, target, importer.WGEasyOptions{DBPath: *dbPath, Source: *srcIface, Owner: *owner, DryRun: *dry})
	} else {
		rep, err = importer.WGDashboard(ctx, st, target, importer.Options{DBPath: *dbPath, Interface: *iface, Owner: *owner, DryRun: *dry})
	}
	fmt.Print(rep.String())
	if err != nil {
		fmt.Fprintln(os.Stderr, "awgdash:", err)
		return 1
	}
	if len(rep.Skipped) > 0 {
		return 1
	}
	return 0
}

// findInterface ищет интерфейс по имени среди известных хабу (он попадает в БД при обходе).
func findInterface(ctx context.Context, st *store.Store, name string) (store.Interface, error) {
	list, err := st.Interfaces(ctx, 0)
	if err != nil {
		return store.Interface{}, err
	}
	for _, i := range list {
		if i.Name == name {
			return i, nil
		}
	}
	known := ""
	for _, i := range list {
		known += " " + i.Name
	}
	if known == "" {
		known = " (панель ещё не обошла ни одного интерфейса — запустите сервис хотя бы раз)"
	}
	return store.Interface{}, fmt.Errorf("интерфейс %q не найден в БД панели; известны:%s", name, known)
}
