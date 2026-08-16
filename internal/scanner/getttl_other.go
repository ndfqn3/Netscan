//go:build !windows

package scanner

import (
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// getTTL 通过 ICMP Echo 应答获取目标主机 IP 包的 TTL(Unix 平台)
func getTTL(ip string, timeout time.Duration) int {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return 0
	}
	defer conn.Close()

	pc := conn.IPv4PacketConn()
	pc.SetControlMessage(ipv4.FlagTTL, true)

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: 0x0ad, Seq: 2, Data: []byte("osdetect")},
	}
	b, _ := msg.Marshal(nil)
	dst, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return 0
	}
	if _, err := conn.WriteTo(b, dst); err != nil {
		return 0
	}

	pc.SetReadDeadline(time.Now().Add(timeout))
	rb := make([]byte, 1500)
	for {
		n, cm, peer, err := pc.ReadFrom(rb)
		if err != nil {
			return 0
		}
		if cm == nil || peer == nil {
			continue
		}
		pa, ok := peer.(*net.IPAddr)
		if !ok || pa.IP.String() != ip {
			continue
		}
		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			continue
		}
		if rm.Type == ipv4.ICMPTypeEchoReply {
			return cm.TTL
		}
	}
}
