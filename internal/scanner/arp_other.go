//go:build !windows

package scanner

// arpAvailable 非 Windows 平台暂不启用 ARP 探测, 回退到 ICMP
func arpAvailable() bool { return false }

func arpPing(ip, srcIP string) bool { return false }
