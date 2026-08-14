package scanner

import (
	"net"
	"testing"
	"time"
)

func TestParsePortSpec(t *testing.T) {
	cases := map[string]int{
		"80":        1,
		"1-100":     100,
		"80,443,8080": 3,
		"22,80-90,443": 13,
		"top-100":    100,
		"top-10":     10,
		"top-2000":   len(topPorts),
	}
	for spec, want := range cases {
		got := len(parsePortSpec(spec))
		if got != want {
			t.Errorf("parsePortSpec(%q) = %d, want %d", spec, got, want)
		}
	}
}

func TestParseTargets(t *testing.T) {
	ips, err := parseTargets([]string{"192.168.1.1-3"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("parsed ips = %v", ips)
	if len(ips) != 3 {
		t.Fatalf("range 192.168.1.1-3 => %d ips, want 3", len(ips))
	}

	ips, err = parseTargets([]string{"10.0.0.0/30"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	// /30 网络位 10.0.0.0, 可用 10.0.0.1 和 10.0.0.2
	if len(ips) != 2 {
		t.Fatalf("10.0.0.0/30 => %d ips, want 2", len(ips))
	}
}

func TestTCPConnectScan(t *testing.T) {
	// 启动一个本地监听, 检测端口应为 open
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
	port := ln.Addr().(*net.TCPAddr).Port

	if st := tcpConnectScan("127.0.0.1", port, time.Second); st != StateOpen {
		t.Errorf("open port state = %s, want open", st)
	}

	// 找一个大概率关闭的端口
	if st := tcpConnectScan("127.0.0.1", 1, time.Second); st != StateClosed {
		t.Errorf("closed port 1 state = %s, want closed", st)
	}
}

func TestLookupService(t *testing.T) {
	if lookupService(22, "tcp") != "ssh" {
		t.Errorf("port 22 => %s, want ssh", lookupService(22, "tcp"))
	}
	if lookupService(80, "tcp") != "http" {
		t.Errorf("port 80 => %s, want http", lookupService(80, "tcp"))
	}
}
