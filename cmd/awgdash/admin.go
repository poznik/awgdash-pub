package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/auth"
	"github.com/poznik/awgdash-pub/internal/config"
	"github.com/poznik/awgdash-pub/internal/store"
)

// adminCmd — `awgdash admin create|passwd|totp|reset-totp|list` (FR-13.2).
// Пароли печатаются один раз в терминал: в БД лежит только argon2id-хеш.
func adminCmd(cfg *config.Config, args []string) int {
	if len(args) == 0 {
		adminUsage()
		return 2
	}
	sub := args[0]
	name := ""
	if len(args) > 1 {
		name = strings.TrimSpace(strings.ToLower(args[1]))
	}
	// Пароль можно подать на stdin — тогда он не светится в списке процессов.
	// --allow-weak разрешает пароль короче минимума: временный, до постоянного.
	fromStdin, allowWeak := false, false
	for _, a := range args[1:] {
		switch a {
		case "--password-stdin":
			fromStdin = true
		case "--allow-weak":
			allowWeak = true
		}
	}
	if sub != "list" && name == "" {
		adminUsage()
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

	switch sub {
	case "create":
		pw, err := readPassword(fromStdin)
		if err != nil {
			return fail(err)
		}
		hash, err := hashPassword(pw, allowWeak)
		if err != nil {
			return fail(err)
		}
		id, err := st.CreateAdmin(ctx, name, hash)
		if err != nil {
			return fail(err)
		}
		st.AddAudit(ctx, store.AuditEntry{Actor: store.ActorSystem, Action: "admin.create", TargetType: "admin", TargetID: id,
			Details: map[string]any{"username": name}, IP: "cli"})
		if fromStdin {
			fmt.Printf("администратор %s создан с заданным паролем\n", name)
		} else {
			fmt.Printf("администратор %s создан\n  пароль: %s\n", name, pw)
			fmt.Println("  запиши его в менеджер паролей — второй раз он не покажется")
		}
		fmt.Printf("  второй фактор: awgdash admin totp %s\n", name)
		return 0

	case "passwd":
		a, err := st.AdminByUsername(ctx, name)
		if err != nil {
			return failAdmin(err, name)
		}
		pw, err := readPassword(fromStdin)
		if err != nil {
			return fail(err)
		}
		hash, err := hashPassword(pw, allowWeak)
		if err != nil {
			return fail(err)
		}
		if err := st.SetPassword(ctx, a.ID, hash); err != nil {
			return fail(err)
		}
		st.AddAudit(ctx, store.AuditEntry{Actor: store.ActorSystem, Action: "admin.passwd", TargetType: "admin", TargetID: a.ID,
			Details: map[string]any{"username": name}, IP: "cli"})
		if fromStdin {
			fmt.Printf("пароль %s заменён заданным; все его сессии закрыты\n", name)
		} else {
			fmt.Printf("пароль %s заменён\n  пароль: %s\n  все сессии этого администратора закрыты\n", name, pw)
		}
		return 0

	case "totp":
		a, err := st.AdminByUsername(ctx, name)
		if err != nil {
			return failAdmin(err, name)
		}
		secret, uri, err := auth.NewTOTP("awgdash", a.Username)
		if err != nil {
			return fail(err)
		}
		// Секрет сохраняется, но второй фактор пока выключен: включает панель после того,
		// как код с телефона сойдётся. Иначе неверно заведённый TOTP закрыл бы вход.
		if err := st.SetTOTP(ctx, a.ID, secret, false); err != nil {
			return fail(err)
		}
		st.AddAudit(ctx, store.AuditEntry{Actor: store.ActorSystem, Action: "admin.totp_new", TargetType: "admin", TargetID: a.ID,
			Details: map[string]any{"username": name}, IP: "cli"})
		fmt.Printf("второй фактор для %s подготовлен (пока выключен)\n", name)
		fmt.Printf("  секрет: %s\n  ссылка: %s\n", secret, uri)
		fmt.Println("  добавь в приложение-аутентификатор и подтверди кодом в панели — тогда он включится")
		return 0

	case "reset-totp":
		a, err := st.AdminByUsername(ctx, name)
		if err != nil {
			return failAdmin(err, name)
		}
		if err := st.SetTOTP(ctx, a.ID, "", false); err != nil {
			return fail(err)
		}
		st.AddAudit(ctx, store.AuditEntry{Actor: store.ActorSystem, Action: "admin.totp_reset", TargetType: "admin", TargetID: a.ID,
			Details: map[string]any{"username": name}, IP: "cli"})
		fmt.Printf("второй фактор для %s сброшен: вход снова по одному паролю\n", name)
		return 0

	case "delete":
		a, err := st.AdminByUsername(ctx, name)
		if err != nil {
			return failAdmin(err, name)
		}
		if err := st.DeleteAdmin(ctx, a.ID); err != nil {
			return fail(err)
		}
		st.AddAudit(ctx, store.AuditEntry{Actor: store.ActorSystem, Action: "admin.delete", TargetType: "admin", TargetID: a.ID,
			Details: map[string]any{"username": name}, IP: "cli"})
		fmt.Printf("администратор %s удалён вместе с его сессиями\n", name)
		return 0

	case "list":
		admins, err := st.Admins(ctx)
		if err != nil {
			return fail(err)
		}
		if len(admins) == 0 {
			fmt.Println("администраторов нет — создай первого: awgdash admin create <имя>")
			return 0
		}
		for _, a := range admins {
			totp := "нет"
			switch {
			case a.TOTPEnabled:
				totp = "включён"
			case a.TOTPSecret != "":
				totp = "подготовлен, не подтверждён"
			}
			last := "ни разу"
			if !a.LastLoginAt.IsZero() {
				last = a.LastLoginAt.Format("2006-01-02 15:04")
			}
			sessions, _ := st.Sessions(ctx, a.ID)
			fmt.Printf("%-16s второй фактор: %-26s вход: %-16s сессий: %d\n", a.Username, totp, last, len(sessions))
		}
		return 0
	}
	adminUsage()
	return 2
}

// hashPassword считает хеш; со слабым паролем предупреждает в терминале — чтобы временный
// пароль не остался постоянным по забывчивости.
func hashPassword(pw string, allowWeak bool) (string, error) {
	if !allowWeak {
		return auth.HashPassword(pw)
	}
	h, err := auth.HashWeak(pw)
	if err == nil && len([]rune(pw)) < auth.MinPasswordLen {
		fmt.Fprintf(os.Stderr, "awgdash: пароль короче %d символов — это временно, замени постоянным\n", auth.MinPasswordLen)
	}
	return h, err
}

// readPassword берёт пароль со stdin или генерирует новый.
func readPassword(fromStdin bool) (string, error) {
	if !fromStdin {
		return auth.NewPassword()
	}
	b, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
	if err != nil {
		return "", err
	}
	pw := strings.TrimRight(string(b), "\r\n")
	if pw == "" {
		return "", fmt.Errorf("на stdin пусто — пароль не задан")
	}
	return pw, nil
}

func adminUsage() {
	fmt.Fprintln(os.Stderr, `использование:
  awgdash admin create <имя>       создать администратора, пароль печатается один раз
                                   (--password-stdin — взять пароль со stdin)
  awgdash admin passwd <имя>       заменить пароль, закрыть все его сессии
                                   (--allow-weak — разрешить пароль короче 12 символов)
  awgdash admin totp <имя>         подготовить второй фактор (включается подтверждением в панели)
  awgdash admin reset-totp <имя>   сбросить второй фактор
  awgdash admin delete <имя>       удалить администратора (последнего — нельзя)
  awgdash admin list               кто заведён`)
}

func fail(err error) int {
	fmt.Fprintln(os.Stderr, "awgdash:", err)
	return 1
}

func failAdmin(err error, name string) int {
	if errors.Is(err, store.ErrNotFound) {
		fmt.Fprintf(os.Stderr, "awgdash: администратора %q нет; создать — awgdash admin create %s\n", name, name)
		return 1
	}
	return fail(err)
}
