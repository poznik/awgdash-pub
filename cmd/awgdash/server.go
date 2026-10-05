package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/config"
	"github.com/poznik/awgdash-pub/internal/humanize"
	"github.com/poznik/awgdash-pub/internal/nodeclient"
	"github.com/poznik/awgdash-pub/internal/store"
)

// serverCmd — `awgdash server add|list|check|enable|disable|rm` (SPEC FR-10.1).
// Реестр узлов парка: хаб ходит к каждому по своему loopback-порту, за которым стоит
// ssh-туннель до той машины.
func serverCmd(cfg *config.Config, args []string) int {
	if len(args) == 0 {
		serverUsage()
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		return fail(fmt.Errorf("БД %s: %w", cfg.DBPath, err))
	}
	defer st.Close()

	switch args[0] {
	case "add":
		return serverAdd(ctx, cfg, st, args[1:])
	case "list":
		return serverList(ctx, cfg, st)
	case "check":
		return serverCheck(ctx, cfg, st, args[1:])
	case "enable", "disable":
		return serverEnable(ctx, st, args[0] == "enable", args[1:])
	case "set":
		return serverSet(ctx, st, args[1:])
	case "retire":
		return serverRetire(ctx, st, args[1:])
	case "return":
		return serverReturn(ctx, st, args[1:])
	case "rm":
		return serverRemove(ctx, st, args[1:])
	default:
		serverUsage()
		return 2
	}
}

func serverUsage() {
	fmt.Fprintln(os.Stderr, `awgdash server — узлы парка

  awgdash server add --slug nl --port 10089 [--title Нидерланды] [--ssh-host nl] [--country NL] [--note …]
                                  завести удалённый узел (порт — локальный конец ssh-туннеля)
  awgdash server list             кто в реестре и отвечает ли
  awgdash server check <слаг>     проверить связь и совместимость версий
  awgdash server set <слаг> [--title Нидерланды] [--country NL]
                                  переименовать сервер или задать страну для флага
  awgdash server enable <слаг>    вернуть узел в работу
  awgdash server disable <слаг>   перестать опрашивать узел, ничего не удаляя
  awgdash server retire <слаг>    вывести узел из парка: машина потеряна или закрыта.
                                  Опрос прекращается, устройства на ней честно показываются
                                  нерабочими, портал их гасит. Обратимо командой return
  awgdash server return <слаг>    вернуть выведенный узел в парк
  awgdash server rm <слаг>        убрать выведенный узел из панели вместе с его интерфейсами,
                                  пирами, устройствами и историей (пользователи остаются)`)
}

func serverAdd(ctx context.Context, cfg *config.Config, st *store.Store, args []string) int {
	var n store.NewServer
	for i := 0; i < len(args); i++ {
		next := func() string {
			if i+1 < len(args) {
				i++
				return args[i]
			}
			return ""
		}
		switch args[i] {
		case "--slug":
			n.Slug = next()
		case "--title":
			n.Title = next()
		case "--ssh-host":
			n.SSHHost = next()
		case "--key":
			n.KeyPath = next()
		case "--country":
			n.Country = next()
		case "--note":
			n.Note = next()
		case "--port":
			n.NodePort, _ = strconv.Atoi(next())
		}
	}
	srv, err := st.AddServer(ctx, n)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("узел %s %s заведён: порт %d, транспорт %s\n", srv.Flag(), srv.Slug, srv.NodePort, srv.Transport)
	// Сразу проверяем связь: узел, добавленный «на будущее», обычно оказывается забыт.
	if err := checkOne(ctx, cfg, srv); err != nil {
		fmt.Printf("  ! связи пока нет: %v\n", err)
		fmt.Println("  подними туннель и повтори: awgdash server check " + srv.Slug)
		return 0
	}
	fmt.Println("  ✓ узел отвечает")
	fmt.Println("  работающая панель возьмёт его в работу в течение минуты")
	return 0
}

func serverList(ctx context.Context, cfg *config.Config, st *store.Store) int {
	list, err := st.Servers(ctx)
	if err != nil {
		return fail(err)
	}
	for _, s := range list {
		state := "включён"
		if !s.Enabled {
			state = "ВЫКЛЮЧЕН"
		}
		if s.Retired() {
			state = "ВЫВЕДЕН"
		}
		where := "локальный"
		if !s.Local() {
			where = fmt.Sprintf("порт %d", s.NodePort)
			if s.SSHHost != "" {
				where += " ← ssh " + s.SSHHost
			}
		}
		seen := "не отвечал"
		if !s.LastSeenAt.IsZero() {
			seen = humanize.Age(s.LastSeenAt) + " назад"
		}
		fmt.Printf("%s %-8s %-10s %-24s %-12s awg %s\n", flagOrPad(s), s.Slug, state, where, seen, s.AWGVersion)
		if s.Local() {
			continue
		}
		if err := checkOne(ctx, cfg, s); err != nil {
			fmt.Printf("           ! %v\n", err)
		}
	}
	return 0
}

func serverCheck(ctx context.Context, cfg *config.Config, st *store.Store, args []string) int {
	if len(args) == 0 {
		serverUsage()
		return 2
	}
	srv, err := st.ServerBySlug(ctx, args[0])
	if err != nil {
		return fail(err)
	}
	if srv.Local() {
		fmt.Println("это локальный узел — проверять связь незачем")
		return 0
	}
	c := nodeclient.New(fmt.Sprintf("http://127.0.0.1:%d", srv.NodePort), cfg.NodeToken)
	h, err := c.CheckCompatible(ctx)
	if err != nil {
		return fail(err)
	}
	fmt.Printf("узел %s: awgdash %s, API %d, awg %s\n", srv.Slug, h.Version, h.API, h.AWGVersion)
	if len(h.Interfaces) > 0 {
		fmt.Printf("  интерфейсы: %s\n", strings.Join(h.Interfaces, ", "))
	}
	if h.ForeignManager != "" {
		fmt.Printf("  ! активен чужой менеджер пиров: %s — запись будет отклонена\n", h.ForeignManager)
	}
	if err := st.TouchServerSeen(ctx, srv.ID); err != nil {
		return fail(err)
	}
	return 0
}

// checkOne — короткая проверка связи для списка и добавления.
func checkOne(ctx context.Context, cfg *config.Config, srv store.Server) error {
	if srv.Local() {
		return nil
	}
	c := nodeclient.New(fmt.Sprintf("http://127.0.0.1:%d", srv.NodePort), cfg.NodeToken)
	_, err := c.CheckCompatible(ctx)
	return err
}

func serverEnable(ctx context.Context, st *store.Store, on bool, args []string) int {
	if len(args) == 0 {
		serverUsage()
		return 2
	}
	srv, err := st.ServerBySlug(ctx, args[0])
	if err != nil {
		return fail(err)
	}
	if err := st.SetServerEnabled(ctx, srv.ID, on); err != nil {
		return fail(err)
	}
	word := "выключен: панель перестанет его опрашивать"
	if on {
		word = "включён"
	}
	fmt.Printf("узел %s %s\n", srv.Slug, word)
	fmt.Println("работающая панель подхватит это в течение минуты")
	return 0
}

func serverRetire(ctx context.Context, st *store.Store, args []string) int {
	if len(args) == 0 {
		serverUsage()
		return 2
	}
	srv, err := st.ServerBySlug(ctx, args[0])
	if err != nil {
		return fail(err)
	}
	if err := st.RetireServer(ctx, srv.ID); err != nil {
		return fail(err)
	}
	b, _ := st.Belongings(ctx, srv.ID)
	fmt.Printf("узел %s выведен из парка; на нём осталось устройств: %d у %d пользователей\n",
		srv.Slug, b.Devices, b.Users)
	fmt.Println("панель снимет его с опроса в течение минуты")
	if b.Devices > 0 {
		fmt.Println("выдайте этим людям конфиги на живом сервере — прежние уже не подключатся")
	}
	return 0
}

func serverReturn(ctx context.Context, st *store.Store, args []string) int {
	if len(args) == 0 {
		serverUsage()
		return 2
	}
	srv, err := st.ServerBySlug(ctx, args[0])
	if err != nil {
		return fail(err)
	}
	if err := st.ReturnServer(ctx, srv.ID); err != nil {
		return fail(err)
	}
	fmt.Printf("узел %s снова в парке; опрос возобновится в течение минуты\n", srv.Slug)
	return 0
}

func serverRemove(ctx context.Context, st *store.Store, args []string) int {
	if len(args) == 0 {
		serverUsage()
		return 2
	}
	srv, err := st.ServerBySlug(ctx, args[0])
	if err != nil {
		return fail(err)
	}
	b, _ := st.Belongings(ctx, srv.ID)
	if err := st.DeleteServer(ctx, srv.ID); err != nil {
		return fail(err)
	}
	fmt.Printf("узел %s убран из панели: интерфейсов %d, пиров %d, устройств %d — вместе с их историей\n",
		srv.Slug, b.Interfaces, b.Peers, b.Devices)
	return 0
}

// flagOrPad — флаг страны или два пробела вместо него, чтобы колонки не съезжали.
func flagOrPad(s store.Server) string {
	if f := s.Flag(); f != "" {
		return f
	}
	return "  "
}

// serverSet меняет человеческое имя сервера и код страны: и то и другое видно людям —
// в выборе сервера и в портале.
func serverSet(ctx context.Context, st *store.Store, args []string) int {
	if len(args) == 0 {
		serverUsage()
		return 2
	}
	srv, err := st.ServerBySlug(ctx, args[0])
	if err != nil {
		return fail(err)
	}
	for i := 1; i < len(args); i++ {
		if i+1 >= len(args) {
			break
		}
		switch args[i] {
		case "--title":
			if err := st.SetServerTitle(ctx, srv.ID, args[i+1]); err != nil {
				return fail(err)
			}
			i++
		case "--country":
			if err := st.SetServerCountry(ctx, srv.ID, args[i+1]); err != nil {
				return fail(err)
			}
			i++
		}
	}
	srv, err = st.ServerBySlug(ctx, args[0])
	if err != nil {
		return fail(err)
	}
	fmt.Printf("%s %s — %s\n", srv.Flag(), srv.Slug, srv.Title)
	return 0
}
