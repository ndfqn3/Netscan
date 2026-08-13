package scanner

import (
	"strings"
	"time"
)

// detectOS 基于 TTL + 开放端口特征启发式识别操作系统
func detectOS(ip string, ports []Port, timeout time.Duration) *OSInfo {
	info := &OSInfo{Confidence: 0}

	ttl := getTTL(ip, timeout)
	info.TTL = ttl

	// 端口特征
	hasRDP := hasPort(ports, 3389, "tcp")
	hasSMB := hasPort(ports, 445, "tcp") || hasPort(ports, 139, "tcp")
	hasSSH := hasPort(ports, 22, "tcp")
	hasNFS := hasPort(ports, 2049, "tcp")
	hasMSSQL := hasPort(ports, 1433, "tcp")
	hasApple := hasPort(ports, 548, "tcp") || hasPort(ports, 22, "tcp")

	switch {
	case ttl == 128 || ttl == 127:
		info.Family = "Windows"
		info.Confidence = 60
	case ttl == 64 || ttl == 63:
		info.Family = "Linux/Unix"
		info.Confidence = 55
	case ttl == 255 || ttl == 254:
		info.Family = "网络设备"
		info.Confidence = 55
	case ttl == 32 || ttl == 31:
		info.Family = "Windows (旧版)"
		info.Confidence = 40
	case ttl > 0:
		info.Family = "未知"
		info.Confidence = 10
	}

	// 结合端口特征调整
	score := map[string]int{}
	addScore := func(name string, w int) { score[name] += w }

	if hasRDP {
		addScore("Windows", 35)
	}
	if hasSMB {
		addScore("Windows", 25)
	}
	if hasMSSQL {
		addScore("Windows", 25)
	}
	if hasSSH {
		addScore("Linux/Unix", 20)
	}
	if hasNFS {
		addScore("Linux/Unix", 30)
	}
	if hasApple {
		addScore("Linux/Unix", 5)
	}

	best := ""
	bestScore := 0
	for name, w := range score {
		if w > bestScore {
			bestScore = w
			best = name
		}
	}
	if best != "" {
		// 如果端口特征与 TTL 家族冲突, 以端口特征为主
		if info.Family != best {
			info.Family = best
			if info.Confidence < 50 {
				info.Confidence = 50
			}
		}
		info.Confidence += 15
		if info.Confidence > 90 {
			info.Confidence = 90
		}
	}

	// 细化具体系统
	info.Name = refineOSName(info.Family, ttl, ports)

	var parts []string
	if ttl > 0 {
		parts = append(parts, "TTL="+itoa(ttl))
	}
	if hasRDP {
		parts = append(parts, "RDP开放")
	}
	if hasSMB {
		parts = append(parts, "SMB开放")
	}
	if hasSSH {
		parts = append(parts, "SSH开放")
	}
	info.Details = strings.Join(parts, ", ")
	if info.Details == "" {
		info.Details = "无指纹信息"
	}
	return info
}

func refineOSName(family string, ttl int, ports []Port) string {
	switch family {
	case "Windows":
		if ttl == 128 {
			return "Microsoft Windows (NT/2000/XP/7/8/10/11)"
		}
		return "Microsoft Windows"
	case "Linux/Unix":
		if hasPort(ports, 22, "tcp") {
			return "Linux 或类 Unix 系统"
		}
		return "Linux/Unix"
	case "网络设备":
		return "路由器/交换机等网络设备"
	default:
		return "未知操作系统"
	}
}

func hasPort(ports []Port, n int, proto string) bool {
	for _, p := range ports {
		if p.Number == n && p.Protocol == proto && p.State == StateOpen {
			return true
		}
	}
	return false
}
