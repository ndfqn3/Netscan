package scanner

import (
	"sync"
	"time"
)

// rateLimiter 简单的令牌调度限速器(限制全局每秒发包数)
type rateLimiter struct {
	mu   sync.Mutex
	rps  int
	next time.Time
}

func newRateLimiter(rps int) *rateLimiter {
	if rps <= 0 {
		return nil
	}
	return &rateLimiter{rps: rps}
}

// wait 阻塞直到允许发送下一个探测包
func (l *rateLimiter) wait() {
	if l == nil || l.rps <= 0 {
		return
	}
	interval := time.Second / time.Duration(l.rps)
	l.mu.Lock()
	now := time.Now()
	var wait time.Duration
	if l.next.After(now) {
		wait = l.next.Sub(now)
		l.next = l.next.Add(interval)
	} else {
		l.next = now.Add(interval)
	}
	l.mu.Unlock()
	if wait > 0 {
		time.Sleep(wait)
	}
}
