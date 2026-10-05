//go:build !linux

package hostmetrics

import (
	"context"
	"os"
	"time"
)

// Info на не-Linux возвращает только hostname.
func (c *Collector) Info(ctx context.Context) (HostInfo, error) {
	h := HostInfo{}
	h.Hostname, _ = os.Hostname()
	return h, nil
}

// Snapshot на не-Linux помечает метрики как неподдерживаемые.
func (c *Collector) Snapshot(ctx context.Context) (Snapshot, error) {
	return Snapshot{At: time.Now(), Supported: false}, nil
}
