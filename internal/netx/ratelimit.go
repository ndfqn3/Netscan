package netx

import (
	"sync"
	"time"
)

// RateLimiter 简单的令牌调度限速器(限制全局每秒发包数)
type RateLimiter struct {
	mu   sync.Mutex
	rps  int
	next time.Time
}

// NewRateLimiter 创建限速器, rps<=0 时返回 nil(不限速)
func NewRateLimiter(rps int) *RateLimiter {
	if rps <= 0 {
		return nil
	}
	return &RateLimiter{rps: rps}
}

// Wait 阻塞直到允许发送下一个探测包
func (l *RateLimiter) Wait() {
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
