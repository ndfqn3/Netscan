package portscan

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/scan"
)

// nerva (Apache-2.0, MIT 兼容) 服务指纹引擎。
// 快速模式只尝试该端口最常见协议, 作为正则探针的兜底识别。
func nervaIdentify(ip string, port int, timeout time.Duration) (string, string, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return "", "", false
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	cfg := scan.Config{DefaultTimeout: timeout, FastMode: false, ScanDepth: "thorough"}
	ctx, cancel := context.WithTimeout(context.Background(), timeout*4)
	defer cancel()
	res, err := scan.ScanTargets(ctx, []plugins.Target{{
		Address: netip.AddrPortFrom(addr, uint16(port)),
		Host:    ip,
	}}, cfg)
	if err != nil || len(res) == 0 {
		return "", "", false
	}
	svc := strings.ToLower(strings.TrimSpace(res[0].Protocol))
	if svc == "" {
		return "", "", false
	}
	return svc, strings.TrimSpace(res[0].Version), true
}
