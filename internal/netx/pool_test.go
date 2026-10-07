package netx

import (
	"context"
	"runtime"
	"testing"
	"time"

	"golang.org/x/sync/semaphore"
)

// TestForEachBoundedGoroutines 验证派发大量任务时协程数受并发上限约束,
// 而不是"先为所有任务创建协程再排队"。
func TestForEachBoundedGoroutines(t *testing.T) {
	const limit = 4
	const tasks = 100000

	sem := semaphore.NewWeighted(limit)
	release := make(chan struct{})
	done := make(chan struct{})

	go func() {
		ForEachBounded(context.Background(), nil, sem, tasks, func(int) {
			<-release // 占住令牌, 模拟阻塞中的探测
		})
		close(done)
	}()

	time.Sleep(200 * time.Millisecond)
	peak := runtime.NumGoroutine()
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ForEachBounded 未在释放后结束")
	}

	if peak > limit*4 {
		t.Fatalf("协程数未受限: peak=%d, 并发上限=%d", peak, limit)
	}
}

// TestForEachBoundedStop 验证停止信号会终止剩余任务派发。
func TestForEachBoundedStop(t *testing.T) {
	sem := semaphore.NewWeighted(2)
	stop := make(chan struct{})
	close(stop)
	var ran int
	ForEachBounded(context.Background(), stop, sem, 1000, func(int) { ran++ })
	if ran != 0 {
		t.Fatalf("停止信号下仍派发了 %d 个任务", ran)
	}
}
