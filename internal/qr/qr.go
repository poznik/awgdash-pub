// Package qr — QR-код конфига в виде inline SVG: страница работает без JS и без внешних картинок (FR-5.4).
package qr

import (
	"fmt"
	"strings"

	"rsc.io/qr"
)

// MaxConfigLen — длина конфига, после которой QR становится плохо сканируемым (FR-4.4).
// Практический предел: 700+ символов уже требуют крупной версии кода и хорошей камеры.
const MaxConfigLen = 1000

// SVG кодирует текст и рисует его модулями по quiet-зоне в 4 модуля.
// scale — сторона модуля в единицах viewBox; итоговый размер задаётся стилями страницы.
func SVG(text string) (string, error) {
	c, err := qr.Encode(text, qr.L)
	if err != nil {
		return "", fmt.Errorf("QR: %w", err)
	}
	const quiet = 4
	side := c.Size + quiet*2
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" class="qr" viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" aria-label="QR-код конфигурации">`, side, side)
	b.WriteString(`<rect width="100%" height="100%" fill="#fff"/><path fill="#000" d="`)
	// Модули одной строки склеиваются в горизонтальные прямоугольники: путь короче, чем рисовать каждый.
	for y := 0; y < c.Size; y++ {
		x := 0
		for x < c.Size {
			if !c.Black(x, y) {
				x++
				continue
			}
			run := 1
			for x+run < c.Size && c.Black(x+run, y) {
				run++
			}
			fmt.Fprintf(&b, "M%d %dh%dv1h-%dz", x+quiet, y+quiet, run, run)
			x += run
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String(), nil
}

// TooLong — текст длиннее порога сканируемости (FR-4.4): повод предупредить администратора.
func TooLong(text string) bool { return len(text) > MaxConfigLen }
