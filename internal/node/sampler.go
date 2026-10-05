package node

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/poznik/awgdash-pub/internal/awg"
)

// Буфер выборок на узле (SPEC FR-10.4). Узел снимает дампы сам, не дожидаясь хаба, и держит
// их сутки. Когда связь с хабом рвётся — а туннель рвётся заметно чаще, чем падает узел, —
// история не теряется: хаб при возврате забирает пропущенное параметром since.
//
// Буфер живёт в памяти: переживать перезапуск узла ему незачем, в этот момент и сам awg
// обычно перезапускается вместе с машиной, а счётчики всё равно начинают отсчёт заново.

const (
	// SampleWindow — сколько держим историю (ТЗ требует сутки).
	SampleWindow = 24 * time.Hour
	// SampleLimit — потолок по числу выборок: при сотнях пиров сутки данных не должны
	// съедать память узла. 5760 выборок — это сутки с шагом 15 секунд.
	SampleLimit = 6000
)

// Sample — снимок интерфейса на момент времени.
type Sample struct {
	At        time.Time      `json:"at"`
	Interface string         `json:"interface"`
	Peers     []awg.PeerDump `json:"peers"`
	// InConf — публичные ключи пиров, которые есть в файле конфига: хабу это нужно, чтобы
	// отличать пира, живущего только в рантайме.
	InConf []string `json:"in_conf,omitempty"`
}

// Buffer — кольцо выборок, ограниченное и по времени, и по числу записей.
type Buffer struct {
	mu     sync.Mutex
	items  []Sample
	window time.Duration
	max    int
}

// NewBuffer создаёт буфер со стандартными ограничениями.
func NewBuffer() *Buffer { return &Buffer{window: SampleWindow, max: SampleLimit} }

// Add кладёт выборку и подрезает старое.
func (b *Buffer) Add(s Sample) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.items = append(b.items, s)
	cutoff := s.At.Add(-b.window)
	drop := 0
	for drop < len(b.items) && b.items[drop].At.Before(cutoff) {
		drop++
	}
	if extra := len(b.items) - drop - b.max; extra > 0 {
		drop += extra
	}
	if drop > 0 {
		b.items = append([]Sample(nil), b.items[drop:]...)
	}
}

// Since возвращает выборки строго новее указанного момента, от старых к новым.
// limit <= 0 означает «все, что есть».
func (b *Buffer) Since(t time.Time, limit int) []Sample {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]Sample, 0, len(b.items))
	for _, s := range b.items {
		if s.At.After(t) {
			out = append(out, s)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// Len — сколько выборок в буфере (для /v1/health и диагностики).
func (b *Buffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.items)
}

// Oldest — время самой старой выборки; нулевое время, если буфер пуст.
func (b *Buffer) Oldest() time.Time {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.items) == 0 {
		return time.Time{}
	}
	return b.items[0].At
}

// Sample снимает дампы всех интерфейсов узла и кладёт их в буфер.
func (n *Node) Sample(ctx context.Context, buf *Buffer) error {
	infos, err := n.Discover(ctx)
	if err != nil {
		return err
	}
	at := time.Now()
	for _, i := range infos {
		_, peers, err := n.Dump(ctx, i.Name)
		if err != nil {
			continue // интерфейс мог быть выключен: остальные это не отменяет
		}
		s := Sample{At: at, Interface: i.Name, Peers: peers}
		if confPeers, err := n.ConfPeers(i.Name); err == nil {
			for _, p := range confPeers {
				s.InConf = append(s.InConf, p.PublicKey)
			}
		}
		buf.Add(s)
	}
	return nil
}

// RunSampler ведёт буфер до отмены контекста. Запускается только на удалённом узле:
// хабу на своей машине буфер не нужен, он и так опрашивает интерфейсы напрямую.
func (n *Node) RunSampler(ctx context.Context, buf *Buffer, every time.Duration, log *slog.Logger) {
	if every <= 0 {
		every = 15 * time.Second
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if err := n.Sample(ctx, buf); err != nil {
			log.Debug("выборка узла", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
