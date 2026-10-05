// Package humanize — единый формат чисел для панели, портала и бота: килобайты, скорости,
// возраст. Один пакет, чтобы «1.2 МБ/с» выглядело одинаково везде.
package humanize

import (
	"fmt"
	"time"
)

// Bytes — объём в десятичных единицах (как показывают провайдеры и awg).
func Bytes(b uint64) string {
	switch {
	case b == 0:
		return "0"
	case b < 1_000_000:
		return fmt.Sprintf("%.0f КБ", float64(b)/1e3)
	case b < 1_000_000_000:
		return fmt.Sprintf("%.1f МБ", float64(b)/1e6)
	case b < 1_000_000_000_000:
		return fmt.Sprintf("%.2f ГБ", float64(b)/1e9)
	default:
		return fmt.Sprintf("%.2f ТБ", float64(b)/1e12)
	}
}

// Bps — скорость. Меньше килобайта в секунду — «0»: показывать «731 Б/с» смысла нет.
func Bps(b uint64) string {
	switch {
	case b < 1_000:
		return "0"
	case b < 1_000_000:
		return fmt.Sprintf("%.0f КБ/с", float64(b)/1e3)
	default:
		return fmt.Sprintf("%.1f МБ/с", float64(b)/1e6)
	}
}

// Age — сколько прошло с момента: «12 мин», «3 ч», «5 дн».
func Age(t time.Time) string {
	if t.IsZero() {
		return "никогда"
	}
	return Dur(time.Since(t))
}

// Dur — длительность крупными единицами (аптайм, возраст хендшейка).
func Dur(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d с", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d мин", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%d ч", int(d.Hours()))
	default:
		return fmt.Sprintf("%d дн", int(d.Hours()/24))
	}
}

// Pct — доля в процентах; нулевой знаменатель даёт прочерк, а не деление на ноль.
func Pct(used, total uint64) string {
	if total == 0 {
		return "—"
	}
	return fmt.Sprintf("%.0f %%", float64(used)/float64(total)*100)
}

// Percent — та же доля числом, для сравнения с порогами.
func Percent(used, total uint64) int {
	if total == 0 {
		return 0
	}
	return int(float64(used) / float64(total) * 100)
}
