//go:build linux

package scanner

import (
	"encoding/binary"
	"net"
	"sync"
	"syscall"
	"time"
)

// rawScanner 基于 raw socket 的无状态扫描器(SYN/FIN/NULL/Xmas/ACK)
type rawScanner struct {
	srcIP   string
	srcPort uint16
	sendFD  int
	recvFD  int
	mu      sync.Mutex
	pending map[string]chan uint8 // "ip:port" -> 返回标志位
	stop    chan struct{}
	once    sync.Once
}

func newRawScanner() (*rawScanner, error) {
	// 通过 UDP 连接探测本地出口 IP
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return nil, err
	}
	srcIP := conn.LocalAddr().(*net.UDPAddr).IP.String()
	conn.Close()

	sendFD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, err
	}
	recvFD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		syscall.Close(sendFD)
		return nil, err
	}

	s := &rawScanner{
		srcIP:   srcIP,
		srcPort: uint16(40000 + time.Now().UnixNano()%20000),
		sendFD:  sendFD,
		recvFD:  recvFD,
		pending: make(map[string]chan uint8),
		stop:    make(chan struct{}),
	}
	go s.receiveLoop()
	return s, nil
}

func (s *rawScanner) close() {
	s.once.Do(func() {
		close(s.stop)
		syscall.Close(s.sendFD)
		syscall.Close(s.recvFD)
	})
}

// probe 发送一个探测包并等待响应
func (s *rawScanner) probe(ip string, port int, flags uint8, timeout time.Duration) PortState {
	key := ip + ":" + itoa(port)
	ch := make(chan uint8, 1)

	s.mu.Lock()
	s.pending[key] = ch
	s.mu.Unlock()

	if err := s.send(ip, port, flags); err != nil {
		s.mu.Lock()
		delete(s.pending, key)
		s.mu.Unlock()
		return StateFiltered
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case got := <-ch:
		switch {
		case flags == flagACK:
			// ACK 扫描: 收到 RST => unfiltered, 无响应 => filtered
			if got&flagRST != 0 {
				return StateUnfiltered
			}
			return StateFiltered
		case flags == flagSYN:
			if got&flagSYN != 0 && got&flagACK != 0 {
				return StateOpen
			}
			if got&flagRST != 0 {
				return StateClosed
			}
			return StateFiltered
		default:
			// FIN/NULL/Xmas: 收到 RST => closed, 无响应 => open|filtered
			if got&flagRST != 0 {
				return StateClosed
			}
			return StateOpenFiltered
		}
	case <-timer.C:
		return StateFiltered
	case <-s.stop:
		return StateFiltered
	}
}

func (s *rawScanner) send(ip string, port int, flags uint8) error {
	dst := net.ParseIP(ip).To4()
	if dst == nil {
		return syscall.EINVAL
	}

	seq := uint32(time.Now().UnixNano() & 0xffffffff)
	hdr := buildTCPHeader(s.srcPort, uint16(port), seq, flags, 1024)
	cksum := tcpChecksum(net.ParseIP(s.srcIP), dst, hdr)
	binary.BigEndian.PutUint16(hdr[16:18], cksum)

	addr := &syscall.SockaddrInet4{
		Port: port,
		Addr: [4]byte{dst[0], dst[1], dst[2], dst[3]},
	}
	return syscall.Sendto(s.sendFD, hdr, 0, addr)
}

func (s *rawScanner) receiveLoop() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		n, _, err := syscall.Recvfrom(s.recvFD, buf, 0)
		if err != nil {
			continue
		}
		pkt := buf[:n]
		if len(pkt) < 40 {
			continue
		}
		ihl := int(pkt[0]&0x0f) * 4
		if len(pkt) < ihl+20 {
			continue
		}
		srcIP := net.IP(pkt[12:16]).String()
		dstIP := net.IP(pkt[16:20]).String()
		if dstIP != s.srcIP {
			continue
		}
		tcp := pkt[ihl:]
		srcPort := binary.BigEndian.Uint16(tcp[0:2])
		dstPort := binary.BigEndian.Uint16(tcp[2:4])
		if dstPort != s.srcPort {
			continue
		}
		flags := tcp[13] & 0x3f
		if flags&flagRST == 0 && flags&flagSYN == 0 && flags&flagACK == 0 {
			continue
		}
		key := srcIP + ":" + itoa(int(srcPort))
		s.mu.Lock()
		ch, ok := s.pending[key]
		s.mu.Unlock()
		if ok {
			select {
			case ch <- flags:
			default:
			}
		}
	}
}

func buildTCPHeader(srcPort, dstPort uint16, seq uint32, flags uint8, window uint16) []byte {
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	binary.BigEndian.PutUint32(hdr[4:8], seq)
	binary.BigEndian.PutUint32(hdr[8:12], 0) // ack
	hdr[12] = 5 << 4                        // data offset
	hdr[13] = flags
	binary.BigEndian.PutUint16(hdr[14:16], window)
	binary.BigEndian.PutUint16(hdr[18:20], 0) // urgent
	return hdr
}

func csum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func tcpChecksum(srcIP, dstIP net.IP, tcp []byte) uint16 {
	pseudo := make([]byte, 0, 12+len(tcp))
	pseudo = append(pseudo, srcIP.To4()...)
	pseudo = append(pseudo, dstIP.To4()...)
	pseudo = append(pseudo, 0, 6) // 协议号 TCP
	pseudo = append(pseudo, byte(len(tcp)>>8), byte(len(tcp)))
	pseudo = append(pseudo, tcp...)
	return csum(pseudo)
}
