package scanner

import (
	"strings"
	"testing"
)

func TestWindowsVersionFromBuild(t *testing.T) {
	cases := map[int]string{
		19041: "Windows 10 2004 (20H1)",
		19045: "Windows 10 22H2",
		20348: "Windows Server 2022",
		17763: "Windows 10 1809 / Server 2019",
		14393: "Windows 10 1607 / Server 2016",
		22621: "Windows 11 22H2",
		22631: "Windows 11 23H2",
		26100: "Windows 11 24H2 / Server 2025",
		9600:  "Windows 8.1 / Server 2012 R2",
		9200:  "Windows 8 / Server 2012",
		7601:  "Windows 7 SP1 / Server 2008 R2",
		2600:  "Windows XP",
	}
	for build, want := range cases {
		got := windowsVersionFromBuild(build)
		if !strings.Contains(got, want) {
			t.Errorf("build %d: got %q, 期望包含 %q", build, got, want)
		}
	}
	// 未知 build 也应有输出
	if s := windowsVersionFromBuild(99999); !strings.Contains(s, "build 99999") {
		t.Errorf("未知 build: %q", s)
	}
}

func TestOpensshToDistro(t *testing.T) {
	cases := map[string]string{
		"7.4":     "CentOS 7 / RHEL 7",
		"9.6p1":   "Ubuntu 24.04 LTS",
		"8.9p1":   "Ubuntu 22.04 LTS",
		"8.2":     "Ubuntu 20.04 LTS",
		"7.6":     "Ubuntu 18.04 LTS",
		"9.2":     "Debian 12",
		"unknown": "",
	}
	for v, want := range cases {
		got := opensshToDistro(v)
		if got != want {
			t.Errorf("OpenSSH %s: got %q, want %q", v, got, want)
		}
	}
}

func TestVulnReport(t *testing.T) {
	r := VulnReport()
	for _, want := range []string{
		"主动利用模块",
		"高危未授权访问检测",
		"漏洞利用模块",
		"漏洞检测模块",
		"弱口令爆破",
		"复现步骤",
		"redis-write-shell",
		"Redis 未授权",
	} {
		if !strings.Contains(r, want) {
			t.Errorf("漏洞报告缺少: %q", want)
		}
	}
}

func TestParsePortSpecMore(t *testing.T) {
	cases := []struct {
		spec string
		n    int
	}{
		{"80", 1},
		{"1-100", 100},
		{"22,80,443", 3},
		{"top-10", 10},
		{"1-10,20", 11},
	}
	for _, c := range cases {
		got := parsePortSpec(c.spec)
		if len(got) != c.n {
			t.Errorf("parsePortSpec(%q) = %d 个端口, want %d", c.spec, len(got), c.n)
		}
	}
}

func TestPrintablePayload(t *testing.T) {
	if s := printablePayload([]byte("INFO\r\n")); s != "INFO" {
		t.Errorf("文本载荷: %q", s)
	}
	if s := printablePayload([]byte{0x11, 0x00, 0x00, 0x00, 0x10}); !strings.Contains(s, "二进制") {
		t.Errorf("二进制载荷: %q", s)
	}
}

func TestVulnDefaultPort(t *testing.T) {
	cases := map[string]int{
		"redis":         6379,
		"mysql":         3306,
		"ssh":           22,
		"docker":        2375,
		"elasticsearch": 9200,
		"unknown":       80,
	}
	for s, want := range cases {
		if got := vulnDefaultPort(s); got != want {
			t.Errorf("vulnDefaultPort(%s) = %d, want %d", s, got, want)
		}
	}
}
