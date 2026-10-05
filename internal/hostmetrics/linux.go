//go:build linux

package hostmetrics

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Info читает hostname, ядро, egress-интерфейс и публичный адрес (по маршруту к 1.1.1.1).
func (c *Collector) Info(ctx context.Context) (HostInfo, error) {
	h := HostInfo{}
	h.Hostname, _ = os.Hostname()
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		h.Kernel = strings.TrimSpace(string(b))
	}
	if c.run != nil {
		out, err := c.run(ctx, "ip", "-4", "route", "get", "1.1.1.1")
		if err != nil {
			return h, fmt.Errorf("ip route get: %w", err)
		}
		f := strings.Fields(out)
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "dev":
				h.EgressIface = f[i+1]
			case "src":
				h.PublicIP = f[i+1]
			}
		}
	}
	return h, nil
}

// Snapshot собирает метрики; первая выборка даёт CPU и сеть без скорости (нет базы для дельты).
func (c *Collector) Snapshot(ctx context.Context) (Snapshot, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	s := Snapshot{At: now, Supported: true}
	if cur, err := readCPU(); err == nil {
		if c.prevCPU.total > 0 && cur.total > c.prevCPU.total {
			dt := float64(cur.total - c.prevCPU.total)
			di := float64(cur.idle - c.prevCPU.idle)
			s.CPUPercent = (1 - di/dt) * 100
		}
		c.prevCPU = cur
	}
	readMem(&s)
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		f := strings.Fields(string(b))
		if len(f) >= 2 {
			s.Load1, _ = strconv.ParseFloat(f[0], 64)
			s.Load5, _ = strconv.ParseFloat(f[1], 64)
		}
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs("/", &st); err == nil {
		s.DiskTotal = st.Blocks * uint64(st.Bsize)
		s.DiskUsed = (st.Blocks - st.Bfree) * uint64(st.Bsize)
	}
	if b, err := os.ReadFile("/proc/uptime"); err == nil {
		if f := strings.Fields(string(b)); len(f) > 0 {
			s.UptimeSeconds, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		s.Kernel = strings.TrimSpace(string(b))
	}
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		s.RebootRequired = true
	}
	iface := c.iface
	if iface == "" {
		if info, err := c.Info(ctx); err == nil {
			iface = info.EgressIface
			c.iface = iface
		}
	}
	s.NetIface = iface
	if iface != "" {
		rx := readUint("/sys/class/net/" + iface + "/statistics/rx_bytes")
		tx := readUint("/sys/class/net/" + iface + "/statistics/tx_bytes")
		s.NetRxBytes, s.NetTxBytes = rx, tx
		if !c.prevTime.IsZero() {
			dt := now.Sub(c.prevTime).Seconds()
			if dt > 0 && rx >= c.prevNet[0] && tx >= c.prevNet[1] {
				s.NetRxBps = float64(rx-c.prevNet[0]) / dt
				s.NetTxBps = float64(tx-c.prevNet[1]) / dt
			}
		}
		c.prevNet = [2]uint64{rx, tx}
	}
	c.prevTime = now
	return s, nil
}

func readCPU() (cpuTimes, error) {
	f, err := os.Open("/proc/stat")
	if err != nil {
		return cpuTimes{}, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 || fields[0] != "cpu" {
			continue
		}
		var t cpuTimes
		for i, v := range fields[1:] {
			n, _ := strconv.ParseUint(v, 10, 64)
			t.total += n
			if i == 3 || i == 4 { // idle + iowait
				t.idle += n
			}
		}
		return t, nil
	}
	return cpuTimes{}, fmt.Errorf("нет строки cpu в /proc/stat")
}

func readMem(s *Snapshot) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return
	}
	defer f.Close()
	m := map[string]uint64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fs := strings.Fields(v)
		if len(fs) == 0 {
			continue
		}
		n, _ := strconv.ParseUint(fs[0], 10, 64)
		m[k] = n * 1024
	}
	s.MemTotal = m["MemTotal"]
	s.MemUsed = m["MemTotal"] - m["MemAvailable"]
	s.SwapTotal = m["SwapTotal"]
	s.SwapUsed = m["SwapTotal"] - m["SwapFree"]
}

func readUint(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return n
}
