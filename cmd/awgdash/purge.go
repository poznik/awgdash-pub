package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/poznik/awgdash-pub/internal/config"
	"github.com/poznik/awgdash-pub/internal/store"
)

// purgeCmd — `awgdash purge [--older <дней>] [--dry-run]`: окончательно удалить содержимое корзины.
// Хаб делает это сам раз в час по сроку в 30 дней; команда нужна, когда убрать надо сейчас.
func purgeCmd(cfg *config.Config, args []string) int {
	fs := flag.NewFlagSet("purge", flag.ContinueOnError)
	days := fs.Int("older", 30, "удалять то, что лежит в корзине дольше стольких дней (0 — всё)")
	dry := fs.Bool("dry-run", false, "показать, что будет удалено")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "awgdash: БД %s: %v\n", cfg.DBPath, err)
		return 1
	}
	defer st.Close()

	older := time.Duration(*days) * 24 * time.Hour
	if *dry {
		devs, err := st.DeletedDevices(ctx)
		if err != nil {
			return fail(err)
		}
		cut := time.Now().Add(-older)
		n := 0
		for _, d := range devs {
			if d.DeletedAt.After(cut) {
				continue
			}
			fmt.Printf("  устройство «%s» (%s), в корзине с %s\n", d.Name, d.Address, d.DeletedAt.Format("2006-01-02 15:04"))
			n++
		}
		fmt.Printf("будет удалено устройств: %d (и пользователи, у которых не осталось устройств)\n", n)
		return 0
	}
	users, devices, err := st.PurgeDeleted(ctx, older)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("окончательно удалено: пользователей %d, устройств %d\n", users, devices)
	return 0
}
