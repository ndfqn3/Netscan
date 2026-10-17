package portscan

import "testing"

func TestRangeUpperBoundNoWrap(t *testing.T) {
	ips, err := rangeToIPs("255.255.255.250-255.255.255.255", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 6 {
		t.Fatalf("want 6, got %d", len(ips))
	}
	if ips[5] != "255.255.255.255" {
		t.Fatalf("unexpected last: %s", ips[5])
	}
}

func TestCIDRUpperBoundNoWrap(t *testing.T) {
	ips, err := cidrToIPs("255.255.255.255/32", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "255.255.255.255" {
		t.Fatalf("%v", ips)
	}
	ips, err = cidrToIPs("255.255.255.254/31", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("want 2, got %d", len(ips))
	}
}

func TestRangeIPv6EndRejected(t *testing.T) {
	if _, err := rangeToIPs("192.168.1.1-2001:db8::1", 10); err == nil {
		t.Fatal("IPv6 终点应返回错误")
	}
}

func TestParsePortSpecBounds(t *testing.T) {
	if ps := parsePortSpec("65536-70000"); len(ps) != 0 {
		t.Fatalf("越界范围应拒绝, got %v", ps)
	}
	if ps := parsePortSpec("0-0"); len(ps) != 0 {
		t.Fatalf("端口 0 应拒绝, got %v", ps)
	}
	for _, p := range parsePortSpec("65530-65540") {
		if p < 1 || p > 65535 {
			t.Fatalf("非法端口 %d", p)
		}
	}
}
