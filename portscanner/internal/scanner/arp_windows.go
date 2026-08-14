//go:build windows

package scanner

import (
	"encoding/binary"
	"net"
	"syscall"
	"unsafe"
)

var (
	iphlpapi    = syscall.NewLazyDLL("iphlpapi.dll")
	procSendARP = iphlpapi.NewProc("SendARP")
)

// arpAvailable Windows 上 SendARP 始终可用
func arpAvailable() bool { return true }

// arpPing 通过 ARP 请求判断同网段主机是否存活(二层, 不受 VPN/透明代理影响)
func arpPing(ipStr, srcIP string) bool {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return false
	}
	dest := binary.LittleEndian.Uint32(ip)
	// 指定源 IP, 确保 ARP 从目标所在网段的接口发出
	var src uint32
	if s := net.ParseIP(srcIP).To4(); s != nil {
		src = binary.LittleEndian.Uint32(s)
	}
	mac := make([]byte, 6)
	macLen := uint32(len(mac))
	ret, _, _ := procSendARP.Call(
		uintptr(dest),
		uintptr(src),
		uintptr(unsafe.Pointer(&mac[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	return ret == 0
}
