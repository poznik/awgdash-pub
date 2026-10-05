// Package hostmetrics читает метрики хоста из /proc и /sys (Linux). На других ОС возвращает заглушку.
package hostmetrics

import (
	"context"
	"sync"
	"time"
)

// Snapshot — текущие метрики хоста (SPEC FR-7.1).
type Snapshot struct {
	At             time.Time `json:"at"`
	CPUPercent     float64   `json:"cpu_percent"`
	MemTotal       uint64    `json:"mem_total"`
	MemUsed        uint64    `json:"mem_used"`
	SwapTotal      uint64    `json:"swap_total"`
	SwapUsed       uint64    `json:"swap_used"`
	DiskTotal      uint64    `json:"disk_total"`
	DiskUsed       uint64    `json:"disk_used"`
	Load1          float64   `json:"load1"`
	Load5          float64   `json:"load5"`
	NetIface       string    `json:"net_iface"`
	NetRxBytes     uint64    `json:"net_rx_bytes"`
	NetTxBytes     uint64    `json:"net_tx_bytes"`
	NetRxBps       float64   `json:"net_rx_bps"` // байт/с с прошлого снимка
	NetTxBps       float64   `json:"net_tx_bps"`
	UptimeSeconds  float64   `json:"uptime_seconds"`
	Kernel         string    `json:"kernel"`
	RebootRequired bool      `json:"reboot_required"`
	Supported      bool      `json:"supported"`
}

// HostInfo — редко меняющиеся факты о машине (SPEC §9 /v1/host).
type HostInfo struct {
	Hostname    string `json:"hostname"`
	Kernel      string `json:"kernel"`
	PublicIP    string `json:"public_ip"`
	EgressIface string `json:"egress_iface"`
}

// Collector хранит предыдущий снимок для расчёта скоростей и CPU.
type Collector struct {
	mu       sync.Mutex
	iface    string
	prevCPU  cpuTimes
	prevNet  [2]uint64
	prevTime time.Time
	run      func(ctx context.Context, name string, args ...string) (string, error)
}

type cpuTimes struct{ idle, total uint64 }

// New создаёт сборщик. iface — интерфейс для счётчиков (пусто = определить по маршруту к 1.1.1.1).
// run — исполнитель внешних команд (для `ip route get`).
func New(iface string, run func(ctx context.Context, name string, args ...string) (string, error)) *Collector {
	return &Collector{iface: iface, run: run}
}
