package web

import (
	"testing"
	"time"

	"github.com/poznik/awgdash-pub/internal/store"
)

// Метрики за сутки — это 1440 точек на ряд; без прореживания страница сервера весила 85 КБ
// при бюджете 60. Точки усредняются, а пропуски переживают сжатие.
func TestDownsampleKeepsGaps(t *testing.T) {
	points := make([]store.Point, 0, 1440)
	for i := 0; i < 1440; i++ {
		p := store.Point{TS: int64(i * 60), Rx: 1000, Tx: 100}
		if i == 700 {
			p = store.Point{TS: int64(i * 60), Gap: true}
		}
		points = append(points, p)
	}
	out := downsample(points, maxChartPoints)
	if len(out) > maxChartPoints+1 {
		t.Fatalf("после сжатия %d точек, ожидалось не больше %d", len(out), maxChartPoints+1)
	}
	gaps := 0
	for _, p := range out {
		if p.Gap {
			gaps++
		}
	}
	if gaps != 1 {
		t.Fatalf("пропусков после сжатия: %d, ожидался один", gaps)
	}
	// Короткий ряд не трогаем.
	short := points[:10]
	if len(downsample(short, maxChartPoints)) != 10 {
		t.Fatal("короткий ряд изменён")
	}
}

func TestChartBreaksLineOnGap(t *testing.T) {
	s := &Server{TZ: time.UTC}
	points := []store.Point{
		{TS: 0, Rx: 10}, {TS: 60, Rx: 20},
		{TS: 120, Gap: true},
		{TS: 180, Rx: 30}, {TS: 240, Rx: 40},
	}
	c := s.buildChart(points, time.Minute, 100, 40, unitBytes, 1)
	if len(c.Down) != 2 {
		t.Fatalf("сегментов линии: %d, ожидалось 2 — пропуск обязан её рвать", len(c.Down))
	}
	if len(c.Gaps) != 1 {
		t.Fatalf("заштрихованных промежутков: %d", len(c.Gaps))
	}
	if c.Empty {
		t.Fatal("график с данными считается пустым")
	}
	// Ряд без трафика помечается пустым, чтобы подпись говорила это прямо.
	empty := s.buildChart([]store.Point{{TS: 0}, {TS: 60}}, time.Minute, 100, 40, unitBytes, 1)
	if !empty.Empty {
		t.Fatal("ряд без трафика не помечен пустым")
	}
}
