package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/poznik/awgdash-pub/internal/store"
)

// Chart — данные для рисования графика в шаблоне: SVG собирается разметкой, без библиотек (FR-6.5).
// Считается глазами клиента: Down — то, что устройство скачало (для сервера это отправленное,
// transfer-tx), Up — то, что оно отдало (принятое сервером, transfer-rx). Панель говорит о людях
// и их устройствах, поэтому серверная пара rx/tx разворачивается здесь, один раз.
type Chart struct {
	W, H      int
	Max       uint64
	Down      []string // готовые points для polyline, по сегменту на непрерывный участок
	Up        []string
	Gaps      []ChartGap
	Labels    []ChartLabel
	Empty     bool
	Bucket    time.Duration
	PeakDown  uint64
	TotalDown uint64
	TotalUp   uint64
	Unit      string
	// Сетка и ось значений: без них по линии не прочитать величину (FR-6.5).
	Grid    []float64
	YLabels []ChartY
	Caption string
	// Data — точки для подсказки при наведении: время и значения уже отформатированы,
	// чтобы в браузере не пришлось повторять форматирование чисел и дат.
	Data template.JS
}

// chartPoint — одна точка для подсказки.
type chartPoint struct {
	X    float64 `json:"x"`
	T    string  `json:"t"`
	Down string  `json:"d"`
	Up   string  `json:"u"`
}

// ChartY — подпись на оси значений. Pct — доля высоты сверху, чтобы подпись держалась
// за линию сетки при любой высоте графика.
type ChartY struct {
	Pct  float64
	Text string
}

// Единицы графика: от них зависят подписи оси и итоговая строка под ним.
const (
	unitBytes   = "bytes" // трафик за корзину
	unitBps     = "bps"   // скорость
	unitPercent = "percent"
)

// ChartGap — заштрихованный промежуток: панель в это время не работала (FR-6.7).
type ChartGap struct {
	X, W float64
}

// ChartLabel — подпись на оси времени. Pct — положение в процентах ширины: график тянется
// по ширине колонки, а подписи лежат HTML-слоем, и пиксели viewBox им не подходят.
type ChartLabel struct {
	Pct  float64
	Text string
}

// maxChartPoints — сколько точек имеет смысл рисовать: на графике шириной 480 больше просто не
// различить, а страница от них пухнет (метрики за сутки — это 1440 точек на каждый ряд).
const maxChartPoints = 240

// downsample сжимает ряд до maxChartPoints, усредняя соседние точки. Пропуск переносится:
// если в группе была дыра, дыра остаётся видна.
func downsample(points []store.Point, max int) []store.Point {
	if len(points) <= max || max <= 0 {
		return points
	}
	group := (len(points) + max - 1) / max
	out := make([]store.Point, 0, max+1)
	for i := 0; i < len(points); i += group {
		end := i + group
		if end > len(points) {
			end = len(points)
		}
		var rx, tx uint64
		gap := false
		for _, p := range points[i:end] {
			rx += p.Rx
			tx += p.Tx
			gap = gap || p.Gap
		}
		n := uint64(end - i)
		out = append(out, store.Point{TS: points[i].TS, Rx: rx / n, Tx: tx / n, Gap: gap})
	}
	return out
}

// buildChart раскладывает ряд по холсту. Пропуски рвут линию: соединять точки через простой
// вместо этого означало бы нарисовать трафик, которого никто не измерял.
func (s *Server) buildChart(points []store.Point, bucket time.Duration, w, h int, unit string, scale float64) Chart {
	if scale == 0 {
		scale = 1
	}
	c := Chart{W: w, H: h, Bucket: bucket, Empty: true, Unit: unit}
	if len(points) == 0 {
		c.Caption = "данных пока нет"
		return c
	}
	points = downsample(points, maxChartPoints)
	for _, p := range points {
		if p.Rx > c.Max {
			c.Max = p.Rx
		}
		if p.Tx > c.Max {
			c.Max = p.Tx
		}
		c.TotalDown += p.Tx
		c.TotalUp += p.Rx
		if p.Tx > c.PeakDown {
			c.PeakDown = p.Tx
		}
	}
	if c.Max == 0 {
		c.Max = 1
	}
	c.Empty = c.TotalDown == 0 && c.TotalUp == 0

	step := float64(w) / float64(maxInt(len(points)-1, 1))
	y := func(v uint64) float64 { return float64(h) - float64(v)/float64(c.Max)*float64(h) }

	var down, up strings.Builder
	var gapFrom = -1
	flush := func() {
		if down.Len() > 0 {
			c.Down = append(c.Down, down.String())
			c.Up = append(c.Up, up.String())
		}
		down.Reset()
		up.Reset()
	}
	for i, p := range points {
		x := float64(i) * step
		if p.Gap {
			flush()
			if gapFrom < 0 {
				gapFrom = i
			}
			continue
		}
		if gapFrom >= 0 {
			c.Gaps = append(c.Gaps, ChartGap{X: float64(gapFrom) * step, W: float64(i-gapFrom) * step})
			gapFrom = -1
		}
		if down.Len() > 0 {
			down.WriteByte(' ')
			up.WriteByte(' ')
		}
		fmt.Fprintf(&down, "%.1f,%.1f", x, y(p.Tx))
		fmt.Fprintf(&up, "%.1f,%.1f", x, y(p.Rx))
	}
	if gapFrom >= 0 {
		c.Gaps = append(c.Gaps, ChartGap{X: float64(gapFrom) * step, W: float64(len(points)-gapFrom) * step})
	}
	flush()

	// Подписи: пять засечек, формат по длине окна.
	layout := "15:04"
	if bucket >= 24*time.Hour || time.Since(time.Unix(points[0].TS, 0)) > 48*time.Hour {
		layout = "02.01"
	}
	for i := 0; i < 5; i++ {
		idx := i * (len(points) - 1) / 4
		if idx >= len(points) {
			idx = len(points) - 1
		}
		c.Labels = append(c.Labels, ChartLabel{
			Pct:  float64(idx) * step / float64(w) * 100,
			Text: time.Unix(points[idx].TS, 0).In(s.TZ).Format(layout),
		})
	}
	// Точки для подсказки: показываются при наведении, поэтому пропуски в них не попадают.
	tip := make([]chartPoint, 0, len(points))
	tipLayout := "15:04"
	if bucket >= 24*time.Hour {
		tipLayout = "02.01"
	} else if time.Since(time.Unix(points[0].TS, 0)) > 36*time.Hour {
		tipLayout = "02.01 15:04"
	}
	for i, p := range points {
		if p.Gap {
			continue
		}
		tip = append(tip, chartPoint{
			X:    float64(i) * step,
			T:    time.Unix(p.TS, 0).In(s.TZ).Format(tipLayout),
			Down: formatValue(float64(p.Tx)/scale, unit),
			Up:   formatValue(float64(p.Rx)/scale, unit),
		})
	}
	if raw, err := json.Marshal(tip); err == nil {
		c.Data = template.JS(raw)
	}
	c.buildGrid(scale)
	c.buildCaption(scale)
	return c
}

// buildGrid раскладывает четыре линии сетки и подписывает три из них: максимум, половину и ноль.
// Больше подписей на высоте 8rem сливаются.
func (c *Chart) buildGrid(scale float64) {
	for i := 1; i <= 4; i++ {
		c.Grid = append(c.Grid, float64(c.H)*float64(i)/4)
	}
	for _, share := range []float64{1, 0.5, 0} {
		c.YLabels = append(c.YLabels, ChartY{
			Pct:  (1 - share) * 100,
			Text: formatValue(float64(c.Max)*share/scale, c.Unit),
		})
	}
}

// buildCaption пишет итог под графиком на языке единиц: трафик суммируют, скорость и проценты — нет.
func (c *Chart) buildCaption(scale float64) {
	if c.Empty {
		c.Caption = "за это время значений не было"
		return
	}
	switch c.Unit {
	case unitBytes:
		c.Caption = fmt.Sprintf("пик %s за корзину · всего ↓%s ↑%s", fmtBytes(c.PeakDown), fmtBytes(c.TotalDown), fmtBytes(c.TotalUp))
	default:
		c.Caption = "пик " + formatValue(float64(c.Max)/scale, c.Unit)
	}
}

func formatValue(v float64, unit string) string {
	switch unit {
	case unitPercent:
		return fmt.Sprintf("%.0f%%", v)
	case unitBps:
		return fmtBps(uint64(v))
	default:
		return fmtBytes(uint64(v))
	}
}

// chartRange — окно графика, выбранное на странице (?range=day|week|month).
type chartRange struct {
	Key    string
	Title  string
	Since  time.Time
	Bucket time.Duration
}

func rangeOf(key string) chartRange {
	switch key {
	case "week":
		return chartRange{Key: "week", Title: "7 дней", Since: time.Now().Add(-7 * 24 * time.Hour), Bucket: time.Hour}
	case "month":
		return chartRange{Key: "month", Title: "30 дней", Since: time.Now().Add(-30 * 24 * time.Hour), Bucket: 6 * time.Hour}
	default:
		return chartRange{Key: "day", Title: "24 часа", Since: time.Now().Add(-24 * time.Hour), Bucket: 30 * time.Minute}
	}
}

// chartBucket — корзина под размер набора. Суточный график одного устройства рисуется получасовыми
// корзинами, а график целого интерфейса — часовыми: разницы на глаз нет, а пятиминутки по 600 пирам
// это 177 тысяч строк на запрос и сотня миллисекунд мимо бюджета §7.1.
func chartBucket(rng chartRange, peers int) time.Duration {
	if rng.Key == "day" && peers > 50 {
		return time.Hour
	}
	return rng.Bucket
}

// chartRanges — переключатель окон на странице.
var chartRanges = []chartRange{rangeOf("day"), rangeOf("week"), rangeOf("month")}
