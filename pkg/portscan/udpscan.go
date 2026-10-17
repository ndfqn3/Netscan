package portscan

import (
	"encoding/binary"
	"net"
	"portscanner/internal/netx"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// udpScanner UDP 扫描器(通过 ICMP 端口不可达判断端口关闭)
type udpScanner struct {
	ip       string
	icmpConn *icmp.PacketConn
	mu       sync.Mutex
	pending  map[int]chan bool
	stop     chan struct{}
	once     sync.Once
}

func newUDPScanner(ip string) (*udpScanner, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	s := &udpScanner{
		ip:       ip,
		icmpConn: conn,
		pending:  make(map[int]chan bool),
		stop:     make(chan struct{}),
	}
	go s.recvLoop()
	return s, nil
}

func (s *udpScanner) close() {
	s.once.Do(func() {
		close(s.stop)
		s.icmpConn.Close()
	})
}

func (s *udpScanner) probe(port int, timeout time.Duration) PortState {
	ch := make(chan bool, 1)
	s.mu.Lock()
	s.pending[port] = ch
	s.mu.Unlock()
	// 无论命中/超时/停止, 都清理 pending 条目, 避免 map 泄漏
	defer func() {
		s.mu.Lock()
		delete(s.pending, port)
		s.mu.Unlock()
	}()

	// 发送 UDP 探测包
	conn, err := net.DialTimeout("udp", net.JoinHostPort(s.ip, netx.Itoa(port)), timeout)
	if err != nil {
		return StateFiltered
	}
	conn.Write([]byte("\x00")) // 空探测负载
	conn.Close()

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ch:
		return StateClosed // 收到 ICMP 端口不可达 => 关闭
	case <-timer.C:
		return StateOpenFiltered // 无响应 => 开放或被过滤
	case <-s.stop:
		return StateOpenFiltered
	}
}

func (s *udpScanner) recvLoop() {
	buf := make([]byte, 1500)
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		s.icmpConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := s.icmpConn.ReadFrom(buf)
		if err != nil {
			continue
		}
		rm, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		if rm.Type != ipv4.ICMPTypeDestinationUnreachable || rm.Code != 3 {
			continue
		}
		body, ok := rm.Body.(*icmp.DstUnreach)
		if !ok {
			continue
		}
		dstIP, port := parseUnreachDst(body.Data)
		if port == 0 || dstIP == nil || !dstIP.Equal(net.ParseIP(s.ip)) {
			continue
		}
		s.mu.Lock()
		ch, ok := s.pending[port]
		if ok {
			delete(s.pending, port)
		}
		s.mu.Unlock()
		if ok {
			select {
			case ch <- true:
			default:
			}
		}
	}
}

// parseUnreachDst 从 ICMP 不可达报文内嵌的原始 IP/UDP 包中提取目标 IP 与端口
func parseUnreachDst(data []byte) (net.IP, int) {
	if len(data) < 28 {
		return nil, 0
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl+4 {
		return nil, 0
	}
	if data[9] != 17 { // 仅处理内嵌 UDP
		return nil, 0
	}
	dst := net.IPv4(data[16], data[17], data[18], data[19])
	return dst, int(binary.BigEndian.Uint16(data[ihl+2 : ihl+4]))
}
