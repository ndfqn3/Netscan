package netx

import (
	"context"
	"sync"

	"golang.org/x/sync/semaphore"
)

// ForEachBounded 以受限并发执行 n 个任务, 回调参数为任务下标。
//
// 关键点: 只有成功取到并发令牌后才启动 goroutine。如果反过来
// (先为每个任务 go, 再在 goroutine 内部阻塞等待令牌), 那么
// "每主机一个协程 × 每端口一个协程" 会在排队前就为所有任务分配协程栈:
// 单 IP 全端口 65,535 个协程; /24 网段可达 254 × 65,535 ≈ 1,660 万个,
// 每个协程最低 2~4KB 栈, 瞬时吃掉数十 GB 内存导致 OOM。
//
// stop 可以为 nil; ctx 取消或 stop 关闭时停止派发剩余任务, 并等待已派发任务结束。
func ForEachBounded(ctx context.Context, stop <-chan struct{}, sem *semaphore.Weighted, n int, fn func(i int)) {
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		if err := sem.Acquire(ctx, 1); err != nil {
			break
		}
		if IsStopped(stop) {
			sem.Release(1)
			break
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			defer sem.Release(1)
			fn(i)
		}(i)
	}
	wg.Wait()
}

// IsStopped 非阻塞判断停止信号是否已触发(nil 通道视为未停止)
func IsStopped(stop <-chan struct{}) bool {
	select {
	case <-stop:
		return true
	default:
		return false
	}
}
