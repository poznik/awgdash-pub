package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/config"
	"github.com/poznik/awgdash-pub/internal/store"
	"github.com/poznik/awgdash-pub/internal/wgkey"
)

// seedCmd — `awgdash seed --users 200 --devices 3` (и `--purge`): синтетика для замера бюджетов
// §7.1 на стенде. Устройства заводятся только в БД: пиры на интерфейс не ставятся, живой туннель
// не трогается. Имена помечены префиксом, чтобы `--purge` убрал ровно их.
func seedCmd(cfg *config.Config, args []string) int {
	fs := flag.NewFlagSet("seed", flag.ContinueOnError)
	users := fs.Int("users", 200, "сколько пользователей завести")
	devices := fs.Int("devices", 3, "сколько устройств каждому")
	prefix := fs.String("prefix", "нагрузка-", "префикс имён — по нему же чистится")
	purge := fs.Bool("purge", false, "удалить ранее заведённую синтетику")
	iface := fs.String("interface", "", "интерфейс (по умолчанию первый известный)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "awgdash: БД %s: %v\n", cfg.DBPath, err)
		return 1
	}
	defer st.Close()

	if *purge {
		return seedPurge(ctx, st, *prefix)
	}

	target, err := seedInterface(ctx, st, *iface)
	if err != nil {
		return fail(err)
	}
	started := time.Now()
	made := 0
	for i := 1; i <= *users; i++ {
		name := fmt.Sprintf("%s%03d", *prefix, i)
		id, _, err := st.CreateUser(ctx, store.User{Name: name, Note: "синтетика для замера", MaxDevices: *devices + 2, DefaultInterfaceID: target.ID})
		if err != nil {
			return fail(fmt.Errorf("пользователь %s: %w", name, err))
		}
		for j := 1; j <= *devices; j++ {
			pair, err := wgkey.Generate()
			if err != nil {
				return fail(err)
			}
			addr, err := st.NextAddress(ctx, target)
			if err != nil {
				return fail(err)
			}
			psk, _ := wgkey.PSK()
			if _, err := st.CreateDevice(ctx, store.Device{
				UserID: id, InterfaceID: target.ID, Name: fmt.Sprintf("устройство %d", j),
				PrivateKey: pair.Private, PublicKey: pair.Public, PresharedKey: psk, Address: addr, CreatedBy: "import",
			}); err != nil {
				return fail(fmt.Errorf("устройство %s/%d: %w", name, j, err))
			}
			made++
		}
	}
	fmt.Printf("заведено пользователей %d, устройств %d за %s\n", *users, made, time.Since(started).Round(time.Millisecond))
	fmt.Printf("пиры на интерфейс не ставились; убрать — awgdash seed --purge --prefix %q\n", *prefix)
	return 0
}

func seedPurge(ctx context.Context, st *store.Store, prefix string) int {
	list, _, err := st.Users(ctx, store.UserFilter{Query: prefix, Limit: 10000})
	if err != nil {
		return fail(err)
	}
	n := 0
	for _, u := range list {
		if !strings.HasPrefix(u.Name, prefix) {
			continue
		}
		if err := st.DeleteUser(ctx, u.ID); err != nil {
			return fail(err)
		}
		n++
	}
	users, devices, err := st.PurgeDeleted(ctx, 0)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("синтетика убрана: помечено %d, удалено пользователей %d, устройств %d\n", n, users, devices)
	return 0
}

func seedInterface(ctx context.Context, st *store.Store, name string) (store.Interface, error) {
	list, err := st.Interfaces(ctx, 0)
	if err != nil {
		return store.Interface{}, err
	}
	for _, i := range list {
		if name == "" || i.Name == name {
			return i, nil
		}
	}
	return store.Interface{}, fmt.Errorf("интерфейс %q не найден", name)
}
