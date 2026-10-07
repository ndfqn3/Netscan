package portscan

import (
	"encoding/asn1"
	"encoding/binary"
	"io"
	"net"
	"portscanner/internal/netx"
	"regexp"
	"strings"
	"time"
)

// SPNEGO NegTokenInit 结构(与 go-smb2 完全一致, 用 encoding/asn1 生成正确字节)
type negTokenInit struct {
	MechTypes   []asn1.ObjectIdentifier `asn1:"explicit,optional,tag:0"`
	ReqFlags    asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechToken   []byte                  `asn1:"explicit,optional,tag:2"`
	MechListMIC []byte                  `asn1:"explicit,optional,tag:3"`
}

type negTokenResp struct{}

type initialContextToken struct {
	ThisMech asn1.ObjectIdentifier `asn1:"optional"`
	Init     []negTokenInit        `asn1:"optional,explict,tag:0"`
	Resp     []negTokenResp        `asn1:"optional,explict,tag:1"`
}

var (
	spnegoOid = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
	nlmpOid   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
)

// encodeSpnego 用标准库 asn1 生成 SPNEGO NegTokenInit 封装(与 go-smb2 一致)
func encodeSpnego(ntlm []byte) []byte {
	bs, _ := asn1.Marshal(initialContextToken{
		ThisMech: spnegoOid,
		Init: []negTokenInit{{
			MechTypes: []asn1.ObjectIdentifier{nlmpOid},
			MechToken: ntlm,
		}},
	})
	bs[0] = 0x60 // application tag
	return bs
}

// smbOsDetect 通过 SMB1/SMB2 协商报文提取目标 Windows/Linux 具体版本
// 返回操作系统版本字符串(如 "Windows 10 Pro 19045", "Samba 4.15"), 空表示未识别
func smbOsDetect(ip string, timeout time.Duration) string {
	conn, err := netx.DialTimeout(net.JoinHostPort(ip, netx.Itoa(445)), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// SMB1 Negotiate Protocol Request(NT LM 0.12 + SMB2 方言)
	if _, err := conn.Write(buildSMB1Negotiate()); err != nil {
		return ""
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return ""
	}
	resp := buf[:n]

	// 在响应中搜索操作系统字符串(SMB1 negotiate 响应含 "Server" 字段)
	os := extractOSString(resp)
	if os != "" {
		return os
	}

	// SMB1 未返回, 尝试 SMB2 协商
	if _, err := conn.Write(buildSMB2Negotiate()); err != nil {
		return ""
	}
	buf2 := make([]byte, 4096)
	n2, _ := conn.Read(buf2)
	os = extractOSString(buf2[:n2])
	return os
}

// buildSMB1Negotiate 构造 SMB1 Negotiate Protocol Request
func buildSMB1Negotiate() []byte {
	dialects := []byte("NT LM 0.12\x00\x02SMB 2.002\x00\x02SMB 2.???\x00")
	smbLen := 32 + 1 + 2 + len(dialects)
	pkt := make([]byte, 0, 4+smbLen)
	// NetBIOS 会话头
	pkt = append(pkt, 0x00, 0x00, 0x00, byte(smbLen))
	// SMB 头
	pkt = append(pkt, 0xFF, 'S', 'M', 'B')
	pkt = append(pkt, 0x72) // SMB_COM_NEGOTIATE
	pkt = append(pkt, 0, 0, 0, 0)
	pkt = append(pkt, 0x18) // flags
	pkt = append(pkt, 0x00, 0x00)
	pkt = append(pkt, 0, 0) // pid high
	pkt = append(pkt, make([]byte, 8)...)
	pkt = append(pkt, 0, 0) // reserved
	pkt = append(pkt, 0, 0) // tid
	pkt = append(pkt, 0x01, 0x00)
	pkt = append(pkt, 0, 0) // uid
	pkt = append(pkt, 0, 0) // mid
	pkt = append(pkt, 0x00) // word count
	pkt = append(pkt, byte(len(dialects)), 0x00)
	pkt = append(pkt, dialects...)
	return pkt
}

// buildSMB2Negotiate 构造 SMB2 Negotiate Request
func buildSMB2Negotiate() []byte {
	dialects := []byte{
		0x02, 0x02, // SMB 2.0.2
		0x10, 0x02, // SMB 2.1
		0x00, 0x03, // SMB 3.0
		0x02, 0x03, // SMB 3.0.2
	}
	neg := make([]byte, 36)
	binary.LittleEndian.PutUint16(neg[0:], 36)                      // StructureSize
	binary.LittleEndian.PutUint16(neg[2:], uint16(len(dialects)/2)) // DialectCount
	binary.LittleEndian.PutUint16(neg[4:], 1)                       // SecurityMode
	binary.LittleEndian.PutUint32(neg[8:], 0x44)                    // Capabilities: LARGE_MTU|ENCRYPTION
	// ClientGuid(12:28) 用固定非零值
	copy(neg[12:28], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00})
	body := append(neg, dialects...)

	header := smb2Header(0x00, 0, 0) // NEGOTIATE
	pkt := append(netbiosHeader(len(header)+len(body)), header...)
	pkt = append(pkt, body...)
	return pkt
}

var osStringRe = regexp.MustCompile(`(?i)(Windows[^\x00\r\n]{0,60}|Samba[^\x00\r\n]{0,40}|NetApp[^\x00\r\n]{0,40}|CIFS[^\x00\r\n]{0,40})`)

// extractOSString 从 SMB 响应中提取操作系统版本字符串
func extractOSString(data []byte) string {
	m := osStringRe.Find(data)
	if m == nil {
		return ""
	}
	s := strings.TrimSpace(string(m))
	// 过滤无效字符
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r > 0x7e {
			return ' '
		}
		return r
	}, s)
	s = strings.Join(strings.Fields(s), " ")
	return s
}

// smbOsDetect2 通过 SMB2 + NTLMSSP 提取 Windows 具体版本(现代 Windows, SMB1 关闭时仍有效)
func smbOsDetect2(ip string, timeout time.Duration) string {
	conn, err := netx.DialTimeout(net.JoinHostPort(ip, netx.Itoa(445)), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// SMB2 Negotiate
	if _, err := conn.Write(buildSMB2Negotiate()); err != nil {
		return ""
	}
	if _, err := readSMB(conn); err != nil {
		return ""
	}

	// SMB2 Session Setup(NTLMSSP NEGOTIATE)
	if _, err := conn.Write(buildSMB2SessionSetup()); err != nil {
		return ""
	}
	resp, err := readSMB(conn)
	if err != nil {
		return ""
	}

	// 提取 NTLM CHALLENGE 中的 build number
	build := extractNTLMBuild(resp)
	if build == 0 {
		return ""
	}
	name := windowsVersionFromBuild(build)

	// 附加主机名指纹(区分 Server/Client)
	if host := extractNTLMComputerName(resp); host != "" {
		lower := strings.ToLower(host)
		switch {
		case strings.HasPrefix(lower, "win-") || strings.Contains(lower, "server") || strings.Contains(lower, "dc"):
			name += " (主机名 " + host + ", 疑似服务器)"
		case strings.HasPrefix(lower, "desktop-") || strings.HasPrefix(lower, "pc-") || strings.HasPrefix(lower, "laptop-"):
			name += " (主机名 " + host + ", 客户端)"
		default:
			name += " (主机名 " + host + ")"
		}
	}
	return name
}

// extractNTLMComputerName 从 NTLM CHALLENGE 的 TargetInfo 解析计算机名(AV 对)
func extractNTLMComputerName(data []byte) string {
	idx := bytesIndex(data, []byte("NTLMSSP"))
	if idx < 0 || idx+48 > len(data) {
		return ""
	}
	tiOffset := int(binary.LittleEndian.Uint32(data[idx+44 : idx+48]))
	tiLen := int(binary.LittleEndian.Uint16(data[idx+40 : idx+42]))
	if tiOffset <= 0 || tiLen <= 0 || idx+tiOffset+tiLen > len(data) {
		return ""
	}
	ti := data[idx+tiOffset : idx+tiOffset+tiLen]
	var nbName, dnsName string
	for i := 0; i+4 <= len(ti); {
		avID := binary.LittleEndian.Uint16(ti[i : i+2])
		avLen := int(binary.LittleEndian.Uint16(ti[i+2 : i+4]))
		i += 4
		if i+avLen > len(ti) {
			break
		}
		val := ti[i : i+avLen]
		i += avLen
		switch avID {
		case 0:
			i = len(ti)
		case 1:
			nbName = utf16leToString(val)
		case 2:
			dnsName = utf16leToString(val)
		}
	}
	if dnsName != "" {
		return dnsName
	}
	return nbName
}

func utf16leToString(b []byte) string {
	var sb strings.Builder
	for i := 0; i+1 < len(b); i += 2 {
		c := rune(binary.LittleEndian.Uint16(b[i : i+2]))
		if c == 0 {
			break
		}
		sb.WriteRune(c)
	}
	return sb.String()
}

// readSMB 读取一条完整的 NetBIOS 会话消息(4 字节头 + 负载)
func readSMB(conn net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return nil, err
	}
	length := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	body := make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return append(hdr, body...), nil
}

// buildSMB2SessionSetup 构造 SMB2 Session Setup Request(NTLMSSP NEGOTIATE, SPNEGO 封装)
func buildSMB2SessionSetup() []byte {
	// NTLMSSP NEGOTIATE_MESSAGE(40 字节, 含 Version 字段)
	ntlm := make([]byte, 40)
	copy(ntlm[:8], []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0})
	binary.LittleEndian.PutUint32(ntlm[8:], 1)           // MessageType = NtLmNegotiate
	binary.LittleEndian.PutUint32(ntlm[12:], 0xE2888215) // NegotiateFlags
	ntlm[32] = 0x0a                                      // Version: major 10
	ntlm[39] = 0x0f                                      // NTLM revision

	// SPNEGO NegTokenInit 封装(标准库 asn1 生成, 与 go-smb2 一致)
	sec := encodeSpnego(ntlm)

	header := smb2Header(0x01, 1, 0) // SESSION_SETUP, MessageId=1
	ss := make([]byte, 24)
	binary.LittleEndian.PutUint16(ss[0:], 25)
	ss[3] = 1                                                // SecurityMode
	binary.LittleEndian.PutUint16(ss[12:], 88)               // SecurityBufferOffset
	binary.LittleEndian.PutUint16(ss[14:], uint16(len(sec))) // SecurityBufferLength
	body := append(ss, sec...)
	pkt := append(netbiosHeader(len(header)+len(body)), header...)
	pkt = append(pkt, body...)
	return pkt
}

// smb2Header 构造 64 字节 SMB2 头
func smb2Header(command uint16, messageID uint64, sessionID uint64) []byte {
	h := make([]byte, 64)
	h[0] = 0xFE
	h[1] = 'S'
	h[2] = 'M'
	h[3] = 'B'
	binary.LittleEndian.PutUint16(h[4:], 64) // StructureSize
	binary.LittleEndian.PutUint16(h[6:], 1)  // CreditCharge
	binary.LittleEndian.PutUint16(h[12:], command)
	binary.LittleEndian.PutUint16(h[14:], 1) // CreditRequest
	binary.LittleEndian.PutUint64(h[24:], messageID)
	binary.LittleEndian.PutUint64(h[40:], sessionID)
	return h
}

// netbiosHeader 构造 4 字节 NetBIOS 会话头
func netbiosHeader(length int) []byte {
	return []byte{0x00, byte(length >> 16), byte(length >> 8), byte(length)}
}

// extractNTLMBuild 从 SMB2 Session Setup 响应中提取 NTLM CHALLENGE 的 build number
func extractNTLMBuild(data []byte) int {
	idx := bytesIndex(data, []byte("NTLMSSP"))
	if idx < 0 || idx+56 > len(data) {
		return 0
	}
	// Version 字段在 CHALLENGE 消息固定偏移 48 处, build 在 +2(小端)
	build := int(data[idx+50]) | int(data[idx+51])<<8
	return build
}

func bytesIndex(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return i
		}
	}
	return -1
}

// windowsVersionFromBuild 根据 NTLM build number 精确映射 Windows 具体版本
// build 对照表依据 MS-NLMP 协议规范与微软公开 build 资料整理
func windowsVersionFromBuild(build int) string {
	var name string
	switch build {
	case 26120, 26100:
		name = "Windows 11 24H2 / Server 2025"
	case 22631, 22635:
		name = "Windows 11 23H2"
	case 22621:
		name = "Windows 11 22H2"
	case 22000:
		name = "Windows 11 21H2"
	case 20348:
		name = "Windows Server 2022"
	case 19045:
		name = "Windows 10 22H2"
	case 19044:
		name = "Windows 10 21H2"
	case 19043:
		name = "Windows 10 21H1"
	case 19042:
		name = "Windows 10 20H2"
	case 19041:
		name = "Windows 10 2004 (20H1)"
	case 18363:
		name = "Windows 10 1909"
	case 18362:
		name = "Windows 10 1903"
	case 17763:
		name = "Windows 10 1809 / Server 2019"
	case 17134:
		name = "Windows 10 1803"
	case 16299:
		name = "Windows 10 1709"
	case 15063:
		name = "Windows 10 1703"
	case 14393:
		name = "Windows 10 1607 / Server 2016"
	case 10586:
		name = "Windows 10 1511"
	case 10240:
		name = "Windows 10 1507"
	case 9600:
		name = "Windows 8.1 / Server 2012 R2"
	case 9200:
		name = "Windows 8 / Server 2012"
	case 7601:
		name = "Windows 7 SP1 / Server 2008 R2"
	case 7600:
		name = "Windows 7 / Server 2008 R2"
	case 6003:
		name = "Windows XP SP3"
	case 6002:
		name = "Windows Vista SP2 / Server 2008"
	case 6001:
		name = "Windows Vista SP1 / Server 2008"
	case 6000:
		name = "Windows Vista / Server 2008"
	case 3790:
		name = "Windows XP x64 / Server 2003"
	case 2600:
		name = "Windows XP"
	case 2195:
		name = "Windows 2000"
	case 1381:
		name = "Windows NT 4.0"
	default:
		if build >= 26100 {
			name = "Windows 11 24H2 / Server 2025"
		} else if build >= 22621 {
			name = "Windows 11"
		} else if build >= 22000 {
			name = "Windows 11 21H2"
		} else if build >= 19041 {
			name = "Windows 10 (2004+)"
		} else if build >= 10240 {
			name = "Windows 10"
		} else if build >= 9600 {
			name = "Windows 8.1 / Server 2012 R2"
		} else if build >= 9200 {
			name = "Windows 8 / Server 2012"
		} else if build >= 7600 {
			name = "Windows 7 / Server 2008 R2"
		} else if build >= 6000 {
			name = "Windows Vista / Server 2008"
		} else if build >= 3790 {
			name = "Windows XP / Server 2003"
		} else {
			name = "Windows"
		}
	}
	return name + " (build " + netx.Itoa(build) + ")"
}
