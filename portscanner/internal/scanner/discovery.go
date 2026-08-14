package scanner

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// discoveryProbePorts 主机发现用的 TCP 探测端口
var discoveryProbePorts = []int{80, 443, 22, 445, 3389, 8080, 21, 25}

var (
	icmpOnce sync.Once
	icmpOK   bool
	icmpSeq  uint32
)

// icmpAvailable 检测当前进程是否具备 ICMP 探测权限(需管理员/root)
func icmpAvailable() bool {
	icmpOnce.Do(func() {
		conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
		if err != nil {
			icmpOK = false
			return
		}
		conn.Close()
		icmpOK = true
	})
	return icmpOK
}

// pingICMP 通过 ICMP Echo 判断主机是否存活(权威信号, 应答无法被透明代理伪造)
func pingICMP(ip string, timeout time.Duration) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false
	}
	defer conn.Close()

	// 每次探测使用唯一 ID, 避免并发扫描时串扰
	id := uint16(0x1000 + atomic.AddUint32(&icmpSeq, 1)%0xEFFF)
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{ID: int(id), Seq: 1, Data: []byte("netscan")},
	}
	b, _ := msg.Marshal(nil)
	dst, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return false
	}
	if _, err := conn.WriteTo(b, dst); err != nil {
		return false
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	rb := make([]byte, 1500)
	for {
		n, peer, err := conn.ReadFrom(rb)
		if err != nil {
			return false
		}
		if peer.String() != ip {
			continue
		}
		rm, err := icmp.ParseMessage(1, rb[:n])
		if err != nil {
			continue
		}
		if echo, ok := rm.Body.(*icmp.Echo); ok && rm.Type == ipv4.ICMPTypeEchoReply && echo.ID == int(id) {
			return true
		}
	}
}

// pingTCP 通过 TCP 连接探测主机存活(回退方案)
// 连接成功或收到 RST(connection refused, 说明主机存活但端口关闭)都视为存活
func pingTCP(ip string, timeout time.Duration) bool {
	var wg sync.WaitGroup
	alive := make(chan struct{}, 1)
	reportAlive := func() {
		select {
		case alive <- struct{}{}:
		default:
		}
	}
	for _, port := range discoveryProbePorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			addr := net.JoinHostPort(ip, itoa(p))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				reportAlive()
			} else if isRefused(err) {
				// 目标主机主动回 RST, 说明主机在线
				reportAlive()
			}
		}(port)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-alive:
		return true
	case <-done:
		return false
	}
}

// isHostUp 综合判断主机是否存活
// 优先级: 同网段用 ARP(二层, 最可靠) > ICMP(权威) > TCP(回退)。
func isHostUp(ip string, timeout time.Duration) (bool, time.Duration) {
	start := time.Now()
	var up bool
	switch {
	case isLocalIP(ip) && arpAvailable():
		up = arpPing(ip, localSourceIP(ip))
	case icmpAvailable():
		up = pingICMP(ip, timeout)
	default:
		up = pingTCP(ip, timeout)
	}
	return up, time.Since(start)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
