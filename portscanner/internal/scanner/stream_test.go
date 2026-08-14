package scanner

import (
	"net"
	"sync"
	"testing"
	"time"
)

// TestScanStreaming 验证扫描引擎实时输出结果
func TestScanStreaming(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	openPort := ln.Addr().(*net.TCPAddr).Port

	var mu sync.Mutex
	var results []Result

	opts := DefaultOptions()
	opts.Targets = []string{"127.0.0.1"}
	opts.Ports = itoa(openPort)
	opts.ScanTypes = []ScanType{ScanTCPConnect}
	opts.SkipDiscovery = true
	opts.ServiceDetect = false
	opts.VersionDetect = false
	opts.OSDetect = false
	opts.ResolveDNS = false
	opts.Timeout = time.Second
	opts.Concurrency = 10

	s := NewScanner(opts,
		func(r Result) {
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		},
		func(p Progress) {},
	)
	if err := s.Run(); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	found := false
	for _, r := range results {
		if r.Port == openPort && r.Protocol == "tcp" && r.State == StateOpen {
			found = true
		}
	}
	if !found {
		t.Fatalf("未在结果中找到开放端口 %d, 结果: %+v", openPort, results)
	}
}

// TestDiscoveryOnly 验证仅主机发现模式
func TestDiscoveryOnly(t *testing.T) {
	var mu sync.Mutex
	var results []Result

	opts := DefaultOptions()
	opts.Targets = []string{"127.0.0.1"}
	opts.DiscoveryOnly = true
	opts.SkipDiscovery = true // 跳过真实探测, 直接列出目标
	opts.Timeout = time.Second
	opts.Concurrency = 10

	s := NewScanner(opts,
		func(r Result) {
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
		},
		func(p Progress) {},
	)
	if err := s.Run(); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(results) != 1 || results[0].State != "up" {
		t.Fatalf("仅主机发现应输出 1 条存活结果, 实际: %+v", results)
	}
}
