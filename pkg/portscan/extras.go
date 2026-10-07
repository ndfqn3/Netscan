package portscan

import (
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// PingAny 综合探测主机存活(ARP/ICMP 优先, 无权限时回退 TCP)
func PingAny(ip string, timeout time.Duration) (time.Duration, bool) {
	if timeout <= 0 {
		timeout = time.Second
	}
	up, latency := isHostUp(ip, timeout)
	return latency, up
}

// Ping 对目标进行 ICMP Echo 探测, 返回往返延迟与是否存活
func Ping(ip string, timeout time.Duration) (time.Duration, bool) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return 0, false
	}
	defer conn.Close()

	id := uint16(0x3000 + time.Now().UnixNano()%0x0FFF)
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: int(id), Seq: 1, Data: []byte("netscan-ping")},
	}
	b, _ := msg.Marshal(nil)
	dst, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return 0, false
	}

	start := time.Now()
	if _, err := conn.WriteTo(b, dst); err != nil {
		return 0, false
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	rb := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return 0, false
		}
		if peer.String() != ip {
			continue
		}
		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			continue
		}
		if echo, ok := rm.Body.(*icmp.Echo); ok && rm.Type == ipv4.ICMPTypeEchoReply && echo.ID == int(id) {
			return time.Since(start), true
		}
	}
}

// TraceRoute 通过递增 TTL 的 ICMP Echo 跟踪到目标的路由
// hop 回调依次返回每一跳的 (跳数, 地址, 往返延迟), 地址为 "*" 表示超时
func TraceRoute(ip string, maxHops int, timeout time.Duration, hop func(hop int, addr string, rtt time.Duration)) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return
	}
	defer conn.Close()
	pc := conn.IPv4PacketConn()

	dst, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return
	}
	id := uint16(0x4000 + time.Now().UnixNano()%0x0FFF)

	for ttl := 1; ttl <= maxHops; ttl++ {
		_ = pc.SetTTL(ttl)
		msg := icmp.Message{
			Type: ipv4.ICMPTypeEcho,
			Code: 0,
			Body: &icmp.Echo{ID: int(id), Seq: ttl, Data: []byte("netscan-tr")},
		}
		b, _ := msg.Marshal(nil)
		start := time.Now()
		if _, err := conn.WriteTo(b, dst); err != nil {
			hop(ttl, "*", 0)
			continue
		}

		pc.SetReadDeadline(time.Now().Add(timeout))
		rb := make([]byte, 1500)
		got := false
		for {
			n, _, peer, err := pc.ReadFrom(rb)
			if err != nil {
				break
			}
			rm, err := icmp.ParseMessage(1, rb[:n])
			if err != nil {
				continue
			}
			switch rm.Type {
			case ipv4.ICMPTypeEchoReply:
				if echo, ok := rm.Body.(*icmp.Echo); ok && echo.ID == int(id) && echo.Seq == ttl {
					hop(ttl, peer.String(), time.Since(start))
					return
				}
			case ipv4.ICMPTypeTimeExceeded:
				hop(ttl, peer.String(), time.Since(start))
				got = true
			}
			if got {
				break
			}
		}
		if !got {
			hop(ttl, "*", 0)
		}
	}
}

// GrabBanner 抓取开放端口的原始 banner(先读主动 banner, 为空则发 HTTP 探测)
func GrabBanner(ip string, port int, timeout time.Duration) string {
	if b, err := tcpBanner(ip, port, timeout, nil); err == nil && b != "" {
		return b
	}
	if b, err := tcpBanner(ip, port, timeout, []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")); err == nil {
		return b
	}
	return ""
}
