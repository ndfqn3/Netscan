package scanner

import (
	"net"
	"regexp"
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
	hasMSRPC := hasPort(ports, 135, "tcp")
	hasSSH := hasPort(ports, 22, "tcp")
	hasNFS := hasPort(ports, 2049, "tcp")
	hasMSSQL := hasPort(ports, 1433, "tcp")
	hasApple := hasPort(ports, 548, "tcp")
	hasMySQL := hasPort(ports, 3306, "tcp")
	hasPostgres := hasPort(ports, 5432, "tcp")

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
	if hasMSRPC {
		addScore("Windows", 30)
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
	if hasMySQL {
		addScore("Linux/Unix", 15)
	}
	if hasPostgres {
		addScore("Linux/Unix", 15)
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

	// SMB 精确版本识别(Windows/Samba 具体版本)
	if hasSMB {
		if os := smbOsDetect(ip, timeout); os != "" {
			info.Name = os
			info.Confidence = 95
			if strings.Contains(strings.ToLower(os), "samba") || strings.Contains(strings.ToLower(os), "unix") {
				info.Family = "Linux/Unix"
			} else {
				info.Family = "Windows"
			}
		} else if os := smbOsDetect2(ip, timeout); os != "" {
			info.Name = os
			info.Confidence = 95
			info.Family = "Windows"
		}
	}

	// SSH banner 识别 Linux 发行版
	if hasSSH {
		if os := sshOsDetect(ip, timeout); os != "" {
			info.Name = os
			info.Family = "Linux/Unix"
			info.Confidence = 92
		}
	}

	// HTTP Server 头识别(IIS/Apache/Nginx 版本 → OS)
	if hasPort(ports, 80, "tcp") || hasPort(ports, 443, "tcp") || hasPort(ports, 8080, "tcp") {
		if os := httpOsDetect(ip, timeout); os != "" {
			if info.Confidence < 90 {
				info.Name = os
				if strings.Contains(strings.ToLower(os), "windows") || strings.Contains(strings.ToLower(os), "iis") {
					info.Family = "Windows"
				} else {
					info.Family = "Linux/Unix"
				}
				info.Confidence = 85
			}
		}
	}

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

var distroRe = regexp.MustCompile(`(?i)(Ubuntu[^\s\r\n]*|Debian[^\s\r\n]*|Raspbian[^\s\r\n]*|CentOS[^\s\r\n]*|Fedora[^\s\r\n]*|FreeBSD[^\s\r\n]*|OpenBSD[^\s\r\n]*|NetBSD[^\s\r\n]*|Alpine[^\s\r\n]*|Arch[^\s\r\n]*|Gentoo[^\s\r\n]*|Kali[^\s\r\n]*|Red Hat[^\s\r\n]*|Rocky[^\s\r\n]*|Oracle Linux[^\s\r\n]*)`)

// sshOsDetect 通过 SSH banner 提取 Linux 发行版与版本
func sshOsDetect(ip string, timeout time.Duration) string {
	conn, err := dialTimeout(net.JoinHostPort(ip, itoa(22)), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return ""
	}
	banner := string(buf[:n])
	// 提取 OpenSSH 版本
	sshVer := regexp.MustCompile(`OpenSSH[_-]([^\s\r\n]+)`).FindStringSubmatch(banner)
	ver := ""
	if len(sshVer) > 1 {
		ver = sshVer[1]
	}
	distro := distroRe.FindString(banner)
	if distro == "" {
		// banner 无发行版后缀(如 CentOS/RHEL), 用 OpenSSH 版本映射
		distro = opensshToDistro(ver)
	}
	if distro == "" {
		if ver != "" {
			return "OpenSSH " + ver
		}
		return ""
	}
	if ver != "" {
		return strings.TrimSpace(distro) + " (OpenSSH " + ver + ")"
	}
	return strings.TrimSpace(distro)
}

// opensshToDistro 根据 OpenSSH 版本号推断 Linux 发行版(无 banner 后缀时)
func opensshToDistro(v string) string {
	v = strings.SplitN(v, "p", 2)[0] // 去掉 pN 补丁后缀
	switch v {
	case "6.6":
		return "CentOS 6 / RHEL 6"
	case "6.7":
		return "Debian 8"
	case "7.4":
		return "CentOS 7 / RHEL 7"
	case "7.5":
		return "RHEL 7.4"
	case "7.6":
		return "Ubuntu 18.04 LTS"
	case "7.9":
		return "CentOS 7 / RHEL 7"
	case "8.0":
		return "Ubuntu 19.04 / CentOS 8"
	case "8.2":
		return "Ubuntu 20.04 LTS"
	case "8.4":
		return "CentOS 8 / RHEL 8"
	case "8.7":
		return "Ubuntu 21.10"
	case "8.9":
		return "Ubuntu 22.04 LTS"
	case "9.0":
		return "Ubuntu 22.10"
	case "9.2":
		return "Debian 12"
	case "9.3":
		return "Ubuntu 23.10"
	case "9.6":
		return "Ubuntu 24.04 LTS"
	case "9.7":
		return "Ubuntu 24.10"
	case "9.8", "9.9":
		return "Ubuntu 25.04"
	default:
		return ""
	}
}

// httpOsDetect 通过 HTTP Server 响应头提取操作系统
func httpOsDetect(ip string, timeout time.Duration) string {
	// 仅探测明文 HTTP 端口(443 为 HTTPS, 明文请求无响应, 跳过)
	for _, port := range []int{80, 8080} {
		conn, err := dialTimeout(net.JoinHostPort(ip, itoa(port)), timeout)
		if err != nil {
			continue
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		_, _ = conn.Write([]byte("GET / HTTP/1.0\r\nHost: " + ip + "\r\n\r\n"))
		buf := make([]byte, 4096)
		n, _ := conn.Read(buf)
		conn.Close()
		resp := string(buf[:n])
		if m := regexp.MustCompile(`(?i)Server:\s*([^\r\n]+)`).FindStringSubmatch(resp); len(m) > 1 {
			server := strings.TrimSpace(m[1])
			if strings.Contains(strings.ToLower(server), "microsoft-iis") {
				if v := regexp.MustCompile(`Microsoft-IIS/([\d.]+)`).FindStringSubmatch(server); len(v) > 1 {
					return iisOS(v[1])
				}
				return "Microsoft IIS"
			}
			// Apache/Nginx 等带 (Ubuntu)/(Debian) 发行版标注
			if d := regexp.MustCompile(`\((Ubuntu[^)]*|Debian[^)]*|CentOS[^)]*|Fedora[^)]*)\)`).FindStringSubmatch(server); len(d) > 1 {
				return d[1]
			}
			return ""
		}
	}
	return ""
}

// iisOS 根据 IIS 版本推断 Windows 版本
func iisOS(ver string) string {
	switch {
	case strings.HasPrefix(ver, "10."):
		return "Windows 10 / Server 2016+ (IIS " + ver + ")"
	case strings.HasPrefix(ver, "8.5"):
		return "Windows Server 2012 R2 (IIS " + ver + ")"
	case strings.HasPrefix(ver, "8.0"):
		return "Windows Server 2012 / Windows 8 (IIS " + ver + ")"
	case strings.HasPrefix(ver, "7.5"):
		return "Windows Server 2008 R2 / Windows 7 (IIS " + ver + ")"
	case strings.HasPrefix(ver, "6.0"):
		return "Windows Server 2003 (IIS " + ver + ")"
	default:
		return "Windows (IIS " + ver + ")"
	}
}
