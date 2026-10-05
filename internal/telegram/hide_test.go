package telegram

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Токен бота не должен попадать в текст ошибки: URL Bot API содержит токен, а сетевые ошибки
// Go несут URL в тексте — без маскирования полный токен утекал в journald (аудит, находка №10).
func TestTokenHiddenInError(t *testing.T) {
	c := NewClient("1234567890:SECRET-TOKEN-VALUE")
	c.API = "http://127.0.0.1:1" // порт заведомо закрыт — получаем ошибку соединения с URL внутри
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := c.GetMe(ctx); err == nil {
		t.Skip("ожидалась ошибка соединения")
	} else if strings.Contains(err.Error(), "SECRET-TOKEN-VALUE") {
		t.Fatalf("токен в тексте ошибки: %v", err)
	}
}
