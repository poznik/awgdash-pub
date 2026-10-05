package qr

import (
	"strings"
	"testing"
)

func TestSVGShape(t *testing.T) {
	svg, err := SVG("awgdash")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(svg, "<svg xmlns=") || !strings.HasSuffix(svg, "</svg>") {
		t.Fatalf("не похоже на SVG: %.80s…", svg)
	}
	for _, want := range []string{`viewBox="0 0 29 29"`, `shape-rendering="crispEdges"`, `<path fill="#000" d="M`} {
		if !strings.Contains(svg, want) {
			t.Fatalf("нет %q в SVG", want)
		}
	}
	// Без внешних ссылок и скриптов: страница портала обязана работать без JS и без сети (FR-5.4).
	// xmlns — пространство имён, а не запрос, поэтому проверяем именно загружаемые ссылки.
	for _, bad := range []string{"href=", "src=", "<script", "<image", "url("} {
		if strings.Contains(svg, bad) {
			t.Fatalf("в SVG оказалось %q", bad)
		}
	}
}

// Конфиг AmneziaWG с 12 параметрами обфускации — примерно 600 символов; для роутера с развёрнутым
// списком AllowedIPs — около 900. Оба должны кодироваться.
func TestSVGRealisticConfigSizes(t *testing.T) {
	for _, n := range []int{600, 900, MaxConfigLen} {
		text := strings.Repeat("A", n)
		svg, err := SVG(text)
		if err != nil {
			t.Fatalf("конфиг длиной %d: %v", n, err)
		}
		if len(svg) < 100 {
			t.Fatalf("подозрительно короткий SVG для %d символов: %d байт", n, len(svg))
		}
	}
}

func TestTooLong(t *testing.T) {
	if TooLong(strings.Repeat("A", MaxConfigLen)) {
		t.Fatal("порог сработал раньше времени")
	}
	if !TooLong(strings.Repeat("A", MaxConfigLen+1)) {
		t.Fatal("порог не сработал")
	}
}
