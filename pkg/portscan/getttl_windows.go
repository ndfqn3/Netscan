//go:build windows

package portscan

import (
	"os/exec"
	"regexp"
	"strconv"
	"time"
)

var ttlRe = regexp.MustCompile(`(?i)TTL[=:]\s*(\d+)`)

// getTTL 通过 ping 命令获取目标主机 TTL(Windows 平台, 系统不支持 ICMP TTL 控制消息)
func getTTL(ip string, timeout time.Duration) int {
	if timeout < time.Second {
		timeout = time.Second
	}
	ms := timeout.Milliseconds()
	if ms < 1000 {
		ms = 1000
	}
	cmd := exec.Command("ping", "-n", "1", "-w", strconv.FormatInt(ms, 10), ip)
	out, err := cmd.Output()
	if err != nil {
		return 0
	}
	m := ttlRe.FindSubmatch(out)
	if m == nil {
		return 0
	}
	ttl, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return 0
	}
	return ttl
}
