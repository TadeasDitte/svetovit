package scanner

import (
	"fmt"
	"sync"
	"time"
)

const DefaultAggressivity = 3

func Aggressivity(level int) (workers, opsPerSecond int, err error) {
	switch level {
	case 1:
		return 1, 100, nil
	case 2:
		return 2, 500, nil
	case 3:
		return DefaultWorkers, 0, nil
	case 4:
		return 8, 0, nil
	case 5:
		return 16, 0, nil
	}
	return 0, 0, fmt.Errorf("aggressivity must be 1-5, got %d", level)
}

type pacer struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
}

func newPacer(opsPerSecond int) *pacer {
	if opsPerSecond <= 0 {
		return nil
	}
	return &pacer{interval: time.Second / time.Duration(opsPerSecond)}
}

func (p *pacer) wait() {
	if p == nil {
		return
	}
	p.mu.Lock()
	now := time.Now()
	if p.next.Before(now) {
		p.next = now
	}
	at := p.next
	p.next = p.next.Add(p.interval)
	p.mu.Unlock()
	time.Sleep(time.Until(at))
}
