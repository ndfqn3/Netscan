package portscan

import (
	"net"
	"portscanner/internal/netx"
	"time"
)

// tcpConnectScan TCP 全连接扫描(三次握手, 最可靠)
func tcpConnectScan(ip string, port int, timeout time.Duration) PortState {
	addr := net.JoinHostPort(ip, netx.Itoa(port))
	conn, err := netx.DialTimeout(addr, timeout)
	if err != nil {
		if isRefused(err) {
			return StateClosed
		}
		return StateFiltered
	}
	conn.Close()
	return StateOpen
}

// tcpBanner 建立连接并读取 banner(用于服务/版本识别)
func tcpBanner(ip string, port int, timeout time.Duration, payload []byte) (string, error) {
	addr := net.JoinHostPort(ip, netx.Itoa(port))
	conn, err := netx.DialTimeout(addr, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))

	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return "", err
		}
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return "", err
	}
	return string(buf[:n]), nil
}
