package scanner

import (
	"net"
	"sync"
)

var (
	localNetsOnce sync.Once
	localNets     []*net.IPNet
)

// localSubnets 获取本机所有 IPv4 网段
func localSubnets() []*net.IPNet {
	localNetsOnce.Do(func() {
		ifaces, err := net.Interfaces()
		if err != nil {
			return
		}
		for _, iface := range ifaces {
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipnet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				ip4 := ipnet.IP.To4()
				if ip4 == nil {
					continue
				}
				localNets = append(localNets, &net.IPNet{
					IP:   ip4,
					Mask: ipnet.Mask,
				})
			}
		}
	})
	return localNets
}

// isLocalIP 判断目标 IP 是否与本机处于同一网段
func isLocalIP(ip string) bool {
	target := net.ParseIP(ip).To4()
	if target == nil {
		return false
	}
	for _, n := range localSubnets() {
		if n.Contains(target) {
			return true
		}
	}
	return false
}

// localSourceIP 返回目标所在网段对应的本机接口 IP(用于指定 ARP 出接口)
func localSourceIP(ip string) string {
	target := net.ParseIP(ip).To4()
	if target == nil {
		return ""
	}
	for _, n := range localSubnets() {
		if n.Contains(target) {
			return n.IP.String()
		}
	}
	return ""
}
