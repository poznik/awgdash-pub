// Package config читает настройки из окружения (EnvironmentFile systemd или .env для разработки).
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config — все настройки процесса. Секреты никогда не логируются.
type Config struct {
	Mode        string // hub | node
	Listen      string // 127.0.0.1:10088
	DBPath      string
	DataDir     string
	AWGConfDir  string
	AWGBin      string
	ServerSlug  string
	ServerTitle string
	AdminHost   string
	PortalHost  string
	TZ          string
	NodeToken   string
	SessionKey  string

	// Telegram: пустой токен просто выключает оповещатель — панель работает и без него.
	TelegramToken    string
	TelegramAdminIDs []int64

	// Бэкап: без публичного ключа age копии не делаются — незашифрованных панель не пишет.
	AgeRecipient    string
	BackupSCPTarget string
	EnvFile         string

	SampleEvery  time.Duration
	MetricsEvery time.Duration
	RawRetention time.Duration
	M5Retention  time.Duration
	// JournalRetention — сколько живут записи аудита и события (FR-12.2a).
	JournalRetention time.Duration

	// ForwardedHops — сколько обратных прокси стоит перед панелью. Адрес клиента берётся
	// из хвоста X-Forwarded-For: последние ForwardedHops элементов добавили доверенные прокси,
	// всё, что левее, прислал сам клиент. 0 выключает разбор заголовка (FR-13.1b).
	ForwardedHops int

	// ForeignManagers — чужие менеджеры пиров, при активности которых запись в интерфейс запрещена
	// (guard): systemd-юнит («wg-dashboard.service») или контейнер («docker:wg-easy»).
	ForeignManagers []string
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func envDur(key string, def time.Duration) (time.Duration, error) {
	v := env(key, "")
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

// Load собирает Config из окружения и проверяет обязательные поля.
func Load() (*Config, error) {
	host, _ := os.Hostname()
	slug := host
	if i := strings.IndexByte(slug, '.'); i > 0 {
		slug = slug[:i]
	}
	c := &Config{
		Mode:            env("AWGDASH_MODE", "hub"),
		Listen:          env("AWGDASH_LISTEN", "127.0.0.1:10088"),
		DBPath:          env("AWGDASH_DB", "/var/lib/awgdash/awgdash.db"),
		DataDir:         env("AWGDASH_DATA_DIR", "/var/lib/awgdash"),
		AWGConfDir:      env("AWGDASH_AWG_CONF_DIR", "/etc/amnezia/amneziawg"),
		AWGBin:          env("AWGDASH_AWG_BIN", "awg"),
		ServerSlug:      env("AWGDASH_SERVER_SLUG", slug),
		ServerTitle:     env("AWGDASH_SERVER_TITLE", slug),
		AdminHost:       env("AWGDASH_ADMIN_HOST", ""),
		PortalHost:      env("AWGDASH_PORTAL_HOST", ""),
		TZ:              env("AWGDASH_TZ", "UTC"),
		NodeToken:       env("AWGDASH_NODE_TOKEN", ""),
		TelegramToken:   env("AWGDASH_TELEGRAM_TOKEN", ""),
		AgeRecipient:    env("AWGDASH_AGE_RECIPIENT", ""),
		BackupSCPTarget: env("AWGDASH_BACKUP_SCP_TARGET", ""),
		EnvFile:         env("AWGDASH_ENV_FILE", "/etc/awgdash/awgdash.env"),
		SessionKey:      env("AWGDASH_SESSION_KEY", ""),
	}
	var err error
	if c.SampleEvery, err = envDur("AWGDASH_SAMPLE_EVERY", 15*time.Second); err != nil {
		return nil, err
	}
	if c.MetricsEvery, err = envDur("AWGDASH_METRICS_EVERY", 60*time.Second); err != nil {
		return nil, err
	}
	if c.RawRetention, err = envDur("AWGDASH_RAW_RETENTION", 48*time.Hour); err != nil {
		return nil, err
	}
	// Пятиминутки — промежуточный агрегат: сутки рисуются по сырым записям, неделя и месяц по
	// часовым. Держать их 90 дней значило бы 15 млн строк при 600 активных устройствах.
	if c.M5Retention, err = envDur("AWGDASH_5M_RETENTION", 14*24*time.Hour); err != nil {
		return nil, err
	}
	// Журналы: страница показывает 90 дней (FR-12.2), хранение с запасом — полгода.
	if c.JournalRetention, err = envDur("AWGDASH_JOURNAL_RETENTION", 180*24*time.Hour); err != nil {
		return nil, err
	}
	c.ForwardedHops = 1
	if v := env("AWGDASH_FORWARDED_HOPS", ""); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("AWGDASH_FORWARDED_HOPS: ожидается неотрицательное число, получено %q", v)
		}
		c.ForwardedHops = n
	}
	c.ForeignManagers = strings.Split(env("AWGDASH_FOREIGN_MANAGERS", "wg-dashboard.service"), ",")
	for _, raw := range strings.Split(env("AWGDASH_TELEGRAM_ADMIN_IDS", ""), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("AWGDASH_TELEGRAM_ADMIN_IDS: %q — ожидается числовой id: %w", raw, err)
		}
		c.TelegramAdminIDs = append(c.TelegramAdminIDs, id)
	}
	// Токен без whitelist опаснее выключенного бота: писать ему сможет кто угодно.
	if c.TelegramToken != "" && len(c.TelegramAdminIDs) == 0 {
		return nil, fmt.Errorf("AWGDASH_TELEGRAM_TOKEN задан, а AWGDASH_TELEGRAM_ADMIN_IDS пуст — некому отвечать")
	}
	for i := range c.ForeignManagers {
		c.ForeignManagers[i] = strings.TrimSpace(c.ForeignManagers[i])
	}
	if c.Mode != "hub" && c.Mode != "node" {
		return nil, fmt.Errorf("AWGDASH_MODE: ожидается hub или node, получено %q", c.Mode)
	}
	if _, _, err := splitHostPort(c.Listen); err != nil {
		return nil, fmt.Errorf("AWGDASH_LISTEN: %w", err)
	}
	return c, nil
}

func splitHostPort(s string) (string, int, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return "", 0, fmt.Errorf("нет порта в %q", s)
	}
	p, err := strconv.Atoi(s[i+1:])
	if err != nil || p <= 0 || p > 65535 {
		return "", 0, fmt.Errorf("плохой порт в %q", s)
	}
	return s[:i], p, nil
}

// LoadEnvFile читает файл KEY=VALUE (для локальной разработки) и кладёт значения в окружение,
// не перекрывая уже заданные переменные.
func LoadEnvFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if i := strings.Index(v, " #"); i >= 0 {
			v = strings.TrimSpace(v[:i])
		}
		v = strings.Trim(v, `"'`)
		if _, exists := os.LookupEnv(k); !exists {
			os.Setenv(k, v)
		}
	}
	return nil
}
