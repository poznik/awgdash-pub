package hub

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/backup"
	"github.com/poznik/awgdash-pub/internal/humanize"
	"github.com/poznik/awgdash-pub/internal/store"
	"github.com/poznik/awgdash-pub/internal/telegram"
	"github.com/poznik/awgdash-pub/internal/version"
)

// Резервное копирование (SPEC §6.9). Копия делается ежедневно, после изменений состояния
// и еженедельно вместе с историей; уходит файлом в Telegram и, если задано, по scp.

const (
	// dailyAt — время ежедневной конфигурационной копии в зоне панели.
	dailyHour, dailyMinute = 3, 30
	// weeklyAt — полная копия раз в неделю, через десять минут после ежедневной.
	weeklyHour, weeklyMinute = 3, 40
	// debounce — сколько ждать после изменения состояния, чтобы не делать копию на каждый клик.
	debounce = 5 * time.Minute
	// keepConfig, keepFull — сколько копий держать локально (FR-9.3).
	keepConfig, keepFull = 14, 8
	// telegramLimit — Bot API не принимает файлы больше 50 МБ.
	telegramLimit = 50 << 20
)

// BackupDir — где лежат локальные копии.
func (h *Hub) BackupDir() string { return filepath.Join(h.Cfg.DataDir, "backups") }

// MarkChanged отмечает, что состояние панели изменилось: через пять минут после последнего
// изменения будет свежая копия. Вызывается из аудита — он пишется ровно на действиях.
func (h *Hub) MarkChanged() {
	h.mu.Lock()
	if h.dirtyAt.IsZero() {
		h.dirtyAt = time.Now()
	}
	h.mu.Unlock()
}

// Backup собирает копию: снимок БД, конфиги интерфейсов, .env и манифест — в один
// зашифрованный файл. Возвращает путь и размер.
func (h *Hub) Backup(ctx context.Context, kind backup.Kind) (string, int64, error) {
	if strings.TrimSpace(h.Cfg.AgeRecipient) == "" {
		return "", 0, backup.ErrNoRecipient
	}
	tmpDir, err := os.MkdirTemp(h.Cfg.DataDir, "backup-")
	if err != nil {
		return "", 0, err
	}
	defer os.RemoveAll(tmpDir)

	dbCopy := filepath.Join(tmpDir, "db.sqlite")
	if err := h.Store.SnapshotTo(ctx, dbCopy); err != nil {
		return "", 0, err
	}
	if kind == backup.KindConfig {
		if err := store.StripHistory(ctx, dbCopy); err != nil {
			return "", 0, err
		}
	}
	entries := []backup.Entry{{Name: "db.sqlite", Path: dbCopy}}

	m, err := h.manifest(ctx, kind)
	if err != nil {
		return "", 0, err
	}
	// Конфиги забираются у агентов: у удалённого узла файловой системы под рукой нет,
	// а копия без его конфига не восстановит интерфейс.
	for _, i := range m.Interfaces {
		if i.ConfPath == "" {
			h.Log.Warn("у интерфейса неизвестен путь конфига", "iface", i.Name)
			continue
		}
		agent, err := h.Agent(i.ServerID)
		if err != nil {
			h.Log.Warn("узел интерфейса неизвестен", "iface", i.Name, "err", err)
			continue
		}
		raw, err := agent.ConfRaw(ctx, i.Name)
		if err != nil {
			h.Log.Warn("конфиг интерфейса не прочитан", "iface", i.Name, "err", err)
			continue
		}
		local := filepath.Join(tmpDir, filepath.Base(i.ConfPath))
		if err := os.WriteFile(local, raw, 0o600); err != nil {
			return "", 0, err
		}
		name := "conf/" + filepath.Base(i.ConfPath)
		if i.Server != "" {
			// В парке из нескольких узлов имена конфигов могут совпасть — раскладываем по серверам.
			name = "conf/" + i.Server + "/" + filepath.Base(i.ConfPath)
		}
		entries = append(entries, backup.Entry{Name: name, Path: local})
	}
	// .env нужен, чтобы после восстановления работали сессии, бот и API узла.
	if h.Cfg.EnvFile != "" {
		if _, err := os.Stat(h.Cfg.EnvFile); err == nil {
			entries = append(entries, backup.Entry{Name: "env/" + filepath.Base(h.Cfg.EnvFile), Path: h.Cfg.EnvFile})
		} else {
			h.Log.Warn("env не прочитан", "path", h.Cfg.EnvFile, "err", err)
		}
	}

	dst := filepath.Join(h.BackupDir(), backup.Name(kind, time.Now()))
	size, err := backup.Create(dst, h.Cfg.AgeRecipient, m, entries)
	if err != nil {
		return "", 0, err
	}
	return dst, size, nil
}

// manifest описывает машину и интерфейсы на момент копии.
func (h *Hub) manifest(ctx context.Context, kind backup.Kind) (backup.Manifest, error) {
	m := backup.Manifest{Kind: kind, CreatedAt: time.Now(), Version: version.Version,
		AdminHost: h.Cfg.AdminHost, PortalHost: h.Cfg.PortalHost}
	if v, err := h.Store.SchemaVersion(ctx); err == nil {
		m.Schema = v
	}
	local, err := h.Agent(h.ServerID)
	if err != nil {
		return m, err
	}
	if v, err := local.AWGVersion(ctx); err == nil {
		m.AWGVersion = v
	}
	info, err := local.HostInfo(ctx)
	if err != nil {
		h.Log.Warn("сведения о хосте для манифеста", "err", err)
	}
	m.Server = backup.Server{Slug: h.Cfg.ServerSlug, Hostname: info.Hostname, PublicIP: info.PublicIP,
		EgressIface: info.EgressIface, Kernel: info.Kernel}

	// В копию идут интерфейсы всех серверов парка: восстанавливать по одному узлу
	// можно и из общей копии, а вот собрать её задним числом — нет.
	ifaces, err := h.Store.Interfaces(ctx, 0)
	if err != nil {
		return m, err
	}
	for _, i := range ifaces {
		// Пиры считаются по базе, а не по рантайм-статусу: разовая команда «копия сейчас»
		// работает без циклов опроса, и статус у неё пустой.
		peers, err := h.Store.Peers(ctx, i.ID, false)
		if err != nil {
			return m, err
		}
		conf := i.ConfPath
		if conf == "" {
			// Путь в БД появляется после обхода интерфейсов; до него спрашиваем узел.
			if a, err := h.Agent(i.ServerID); err == nil {
				conf = a.ConfPath(i.Name)
			}
		}
		slug := ""
		if srv, ok := h.servers.get(i.ServerID); ok {
			slug = srv.Slug
		}
		m.Interfaces = append(m.Interfaces, backup.Iface{Name: i.Name, Server: slug, ServerID: i.ServerID, ConfPath: conf,
			Subnet: i.Subnet, ListenPort: i.ListenPort, MTU: i.MTU, Mode: i.Mode, Peers: len(peers), Obfuscation: len(i.Obfuscation)})
	}
	return m, nil
}

// RunBackup делает копию и разносит её: локально, файлом в Telegram и, если задано, по scp.
// Итог пишется событием — молчаливо не удавшийся бэкап хуже отсутствующего.
func (h *Hub) RunBackup(ctx context.Context, kind backup.Kind) (string, error) {
	path, size, err := h.Backup(ctx, kind)
	if err != nil {
		h.event(ctx, "backup_failed", "crit", 0, 0, fmt.Sprintf("копия %s не сделана: %v", kind, err))
		return "", err
	}
	h.Log.Info("копия готова", "kind", kind, "file", filepath.Base(path), "size", size)
	h.event(ctx, "backup_ok", "info", 0, 0, fmt.Sprintf("копия %s готова: %s, %s", kind, filepath.Base(path), humanize.Bytes(uint64(size))))
	h.Store.SetSetting(ctx, "backup_"+string(kind)+"_at", strconv.FormatInt(time.Now().Unix(), 10))

	if kind == backup.KindConfig {
		h.sendBackup(ctx, path, size)
	}
	if target := strings.TrimSpace(h.Cfg.BackupSCPTarget); target != "" {
		if err := h.scpBackup(ctx, path, target); err != nil {
			h.Log.Warn("копия по scp", "target", target, "err", err)
			h.event(ctx, "backup_scp_failed", "warn", 0, 0, "копию не удалось отправить по scp: "+err.Error())
		}
	}
	if err := h.pruneBackups(); err != nil {
		h.Log.Warn("уборка копий", "err", err)
	}
	return path, nil
}

// sendBackup отправляет копию администратору. Файл со всеми ключами уходит зашифрованным —
// расшифровать его может только владелец приватного ключа age.
func (h *Hub) sendBackup(ctx context.Context, path string, size int64) {
	if h.Bot == nil {
		return
	}
	if size > telegramLimit {
		h.Log.Warn("копия больше лимита Telegram", "size", size)
		h.Bot.Send(ctx, "⚠️ <b>копия "+telegram.Esc(filepath.Base(path))+" больше 50 МБ — в чат не влезет</b>")
		return
	}
	data, err := os.ReadFile(path)
	if err != nil {
		h.Log.Warn("чтение копии для отправки", "err", err)
		return
	}
	caption := fmt.Sprintf("копия %s · %s", h.Cfg.ServerSlug, humanize.Bytes(uint64(size)))
	if err := h.Bot.SendFile(ctx, filepath.Base(path), data, caption); err != nil {
		h.Log.Warn("отправка копии", "err", err)
		h.event(ctx, "backup_send_failed", "warn", 0, 0, "копию не удалось отправить в Telegram: "+err.Error())
	}
}

// scpBackup копирует файл на указанный хост. Панель не хранит ssh-ключей: используется
// системный ssh-агент или ключ пользователя awgdash.
func (h *Hub) scpBackup(ctx context.Context, path, target string) error {
	c, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(c, "scp", "-q", "-o", "BatchMode=yes", path, target)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// pruneBackups держит локально 14 ежедневных и 8 недельных копий (FR-9.3).
func (h *Hub) pruneBackups() error {
	entries, err := os.ReadDir(h.BackupDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	byKind := map[backup.Kind][]string{}
	for _, e := range entries {
		name := e.Name()
		switch {
		case strings.HasPrefix(name, "awgdash-config-"):
			byKind[backup.KindConfig] = append(byKind[backup.KindConfig], name)
		case strings.HasPrefix(name, "awgdash-full-"):
			byKind[backup.KindFull] = append(byKind[backup.KindFull], name)
		}
	}
	limits := map[backup.Kind]int{backup.KindConfig: keepConfig, backup.KindFull: keepFull}
	for kind, names := range byKind {
		sort.Sort(sort.Reverse(sort.StringSlice(names))) // имя начинается с даты, поэтому сортировка по имени — по времени
		for i, name := range names {
			if i < limits[kind] {
				continue
			}
			if err := os.Remove(filepath.Join(h.BackupDir(), name)); err != nil {
				return err
			}
			h.Log.Info("старая копия удалена", "file", name)
		}
	}
	return nil
}

// Backups — локальные копии, свежие сверху (для страницы настроек и CLI).
type BackupFile struct {
	Name string
	Size int64
	At   time.Time
}

func (h *Hub) Backups() ([]BackupFile, error) {
	entries, err := os.ReadDir(h.BackupDir())
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []BackupFile
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "awgdash-") || e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, BackupFile{Name: e.Name(), Size: info.Size(), At: info.ModTime()})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].At.After(out[b].At) })
	return out, nil
}

// backupTick — проверка расписания раз в минуту: настало ли время ежедневной или недельной
// копии и не пора ли снять копию после изменений.
func (h *Hub) backupTick(ctx context.Context) error {
	if strings.TrimSpace(h.Cfg.AgeRecipient) == "" {
		return nil // без получателя копии не делаются; о причине говорит doctor и страница настроек
	}
	now := time.Now().In(h.tz())

	h.mu.Lock()
	dirty := h.dirtyAt
	if !dirty.IsZero() && time.Since(dirty) >= debounce {
		h.dirtyAt = time.Time{}
	} else {
		dirty = time.Time{}
	}
	h.mu.Unlock()
	if !dirty.IsZero() {
		h.Log.Info("копия после изменений состояния")
		if _, err := h.RunBackup(ctx, backup.KindConfig); err != nil {
			return err
		}
		return nil
	}

	if due, err := h.dueToday(ctx, "backup_daily_done", now, dailyHour, dailyMinute); err != nil {
		return err
	} else if due {
		if _, err := h.RunBackup(ctx, backup.KindConfig); err != nil {
			return err
		}
		return h.Store.SetSetting(ctx, "backup_daily_done", now.Format("2006-01-02"))
	}
	if now.Weekday() == time.Sunday {
		if due, err := h.dueToday(ctx, "backup_weekly_done", now, weeklyHour, weeklyMinute); err != nil {
			return err
		} else if due {
			if _, err := h.RunBackup(ctx, backup.KindFull); err != nil {
				return err
			}
			return h.Store.SetSetting(ctx, "backup_weekly_done", now.Format("2006-01-02"))
		}
	}
	return nil
}

// dueToday — наступило ли время и не делали ли уже сегодня. Отметка хранится датой:
// панель, поднятая днём после простоя, снимет пропущенную копию сразу, а не будет ждать ночи.
func (h *Hub) dueToday(ctx context.Context, key string, now time.Time, hour, min int) (bool, error) {
	last, err := h.Store.Setting(ctx, key)
	if err != nil {
		return false, err
	}
	if last == now.Format("2006-01-02") {
		return false, nil
	}
	return now.Hour() > hour || (now.Hour() == hour && now.Minute() >= min), nil
}
