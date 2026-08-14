package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// parseTargets 解析目标列表为 IP 地址集合
// 支持: 单 IP, CIDR, IP 范围(192.168.1.1-50), 域名, 逗号分隔
func parseTargets(targets []string) ([]string, error) {
	ips := map[string]bool{}

	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		// 可能包含多个, 用逗号/空格分隔
		items := strings.FieldsFunc(t, func(r rune) bool {
			return r == ',' || r == ' ' || r == ';'
		})
		for _, item := range items {
			expanded, err := expandTarget(item)
			if err != nil {
				return nil, err
			}
			for _, ip := range expanded {
				ips[ip] = true
			}
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("未解析到有效目标")
	}

	out := make([]string, 0, len(ips))
	for ip := range ips {
		out = append(out, ip)
	}
	sort.Slice(out, func(i, j int) bool {
		return ipToUint32(net.ParseIP(out[i])) < ipToUint32(net.ParseIP(out[j]))
	})
	return out, nil
}

// expandTarget 扩展单个目标表达式
func expandTarget(item string) ([]string, error) {
	item = strings.TrimSpace(item)

	// CIDR
	if strings.Contains(item, "/") {
		return cidrToIPs(item)
	}

	// IP 范围 192.168.1.1-50 或 192.168.1.1-192.168.1.50
	if strings.Contains(item, "-") && strings.Count(item, ".") >= 3 {
		return rangeToIPs(item)
	}

	// 纯 IP
	if ip := net.ParseIP(item); ip != nil {
		return []string{ip.String()}, nil
	}

	// 域名解析
	ips, err := net.LookupIP(item)
	if err != nil {
		return nil, fmt.Errorf("无法解析主机 %s: %v", item, err)
	}
	var out []string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			out = append(out, v4.String())
		} else {
			out = append(out, ip.String())
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("主机 %s 无 IPv4 地址", item)
	}
	return out, nil
}

func cidrToIPs(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("无效 CIDR %s: %v", cidr, err)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("暂仅支持 IPv4 CIDR: %s", cidr)
	}
	start := ipToUint32(ip.To4())
	mask := binary.BigEndian.Uint32(ipnet.Mask)
	network := start & mask
	broadcast := network | ^mask

	var out []string
	for i := network + 1; i < broadcast; i++ {
		out = append(out, uint32ToIP(i))
	}
	return out, nil
}

func rangeToIPs(r string) ([]string, error) {
	parts := strings.SplitN(r, "-", 2)
	base := strings.TrimSpace(parts[0])
	end := strings.TrimSpace(parts[1])

	baseIP := net.ParseIP(base)
	if baseIP == nil || baseIP.To4() == nil {
		return nil, fmt.Errorf("无效范围起点 %s", base)
	}

	var endIP net.IP
	if strings.Contains(end, ".") {
		endIP = net.ParseIP(end)
		if endIP == nil {
			return nil, fmt.Errorf("无效范围终点 %s", end)
		}
	} else {
		// 仅最后一段的数字
		last, err := strconv.Atoi(end)
		if err != nil {
			return nil, fmt.Errorf("无效范围终点 %s", end)
		}
		b4 := append(net.IP(nil), baseIP.To4()...)
		b4[3] = byte(last)
		endIP = net.IP(b4)
	}

	start := ipToUint32(baseIP.To4())
	stop := ipToUint32(endIP.To4())
	if stop < start {
		return nil, fmt.Errorf("范围终点小于起点: %s", r)
	}
	var out []string
	for i := start; i <= stop; i++ {
		out = append(out, uint32ToIP(i))
	}
	return out, nil
}

func ipToUint32(ip net.IP) uint32 {
	if len(ip) == 16 {
		ip = ip[12:16]
	}
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip.String()
}
