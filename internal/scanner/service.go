package scanner

import (
	"regexp"
	"strings"
	"time"
)

// serviceProbe 服务识别探针
type serviceProbe struct {
	Name    string
	Payload []byte // nil 表示 null 探针(仅读 banner)
	Regex   *regexp.Regexp
	Service string
	// VersionGroup 从正则捕获组中提取版本, 0 表示用完整匹配
	VersionGroup int
}

// serviceProbes 服务识别探针库(正则指纹)
var serviceProbes = []serviceProbe{
	// ---- 远程登录类 ----
	{Name: "ssh", Payload: nil, Regex: regexp.MustCompile(`SSH-([0-9.]+)-([^\s\r\n]+)`), Service: "ssh", VersionGroup: 0},
	{Name: "telnet", Payload: nil, Regex: regexp.MustCompile(`(?i)telnet`), Service: "telnet", VersionGroup: 0},
	{Name: "rlogin", Payload: nil, Regex: regexp.MustCompile(`(?i)(login:|username:)`), Service: "login", VersionGroup: 0},
	{Name: "rsh", Payload: nil, Regex: regexp.MustCompile(`(?i)\x00`), Service: "unknown", VersionGroup: 0},

	// ---- 文件传输类 ----
	{Name: "ftp", Payload: nil, Regex: regexp.MustCompile(`220[-\s].*?FTP`), Service: "ftp", VersionGroup: 0},
	{Name: "vsftpd", Payload: nil, Regex: regexp.MustCompile(`220[-\s].*?vsFTPd\s+([^\s]+)`), Service: "ftp", VersionGroup: 0},
	{Name: "proftpd", Payload: nil, Regex: regexp.MustCompile(`220[-\s].*?ProFTPD\s+([^\s]+)`), Service: "ftp", VersionGroup: 0},
	{Name: "pureftpd", Payload: nil, Regex: regexp.MustCompile(`220[-\s].*?Pure-FTPd`), Service: "ftp", VersionGroup: 0},
	{Name: "ftp-generic", Payload: nil, Regex: regexp.MustCompile(`220[-\s]([^\r\n]+)`), Service: "ftp", VersionGroup: 1},
	{Name: "rsync", Payload: nil, Regex: regexp.MustCompile(`@RSYNCD:\s+([^\s]+)`), Service: "rsync", VersionGroup: 1},

	// ---- 邮件类 ----
	{Name: "smtp", Payload: nil, Regex: regexp.MustCompile(`220[-\s].*?(?:ESMTP|SMTP|Exim|Postfix|sendmail|Microsoft ESMTP)`), Service: "smtp", VersionGroup: 0},
	{Name: "exim", Payload: nil, Regex: regexp.MustCompile(`(?i)Exim\s+([^\s]+)`), Service: "smtp", VersionGroup: 1},
	{Name: "postfix", Payload: nil, Regex: regexp.MustCompile(`(?i)Postfix`), Service: "smtp", VersionGroup: 0},
	{Name: "sendmail", Payload: nil, Regex: regexp.MustCompile(`(?i)sendmail`), Service: "smtp", VersionGroup: 0},
	{Name: "smtp-generic", Payload: nil, Regex: regexp.MustCompile(`^220[-\s]`), Service: "smtp", VersionGroup: 0},
	{Name: "pop3", Payload: nil, Regex: regexp.MustCompile(`\+OK.*?(?:POP3|pop3|Dovecot|Courier)`), Service: "pop3", VersionGroup: 0},
	{Name: "imap", Payload: nil, Regex: regexp.MustCompile(`\*\s*OK.*?(?:IMAP4|Dovecot|Courier)`), Service: "imap", VersionGroup: 0},
	{Name: "imap-capability", Payload: []byte("a001 CAPABILITY\r\n"), Regex: regexp.MustCompile(`\*\s*CAPABILITY.*?IMAP4`), Service: "imap", VersionGroup: 0},

	// ---- Web 类 ----
	{Name: "http-server", Payload: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"), Regex: regexp.MustCompile(`(?i)Server:\s*([^\r\n]+)`), Service: "http", VersionGroup: 1},
	{Name: "http-status", Payload: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"), Regex: regexp.MustCompile(`(?i)^HTTP/1\.[01]\s+\d{3}`), Service: "http", VersionGroup: 0},
	{Name: "http2-status", Payload: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"), Regex: regexp.MustCompile(`(?i)^HTTP/2\s+\d{3}`), Service: "http", VersionGroup: 0},
	{Name: "nginx", Payload: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"), Regex: regexp.MustCompile(`(?i)Server:\s*nginx/([^\s]+)`), Service: "http", VersionGroup: 0},
	{Name: "apache", Payload: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"), Regex: regexp.MustCompile(`(?i)Server:\s*Apache/([^\s]+)`), Service: "http", VersionGroup: 0},
	{Name: "iis", Payload: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"), Regex: regexp.MustCompile(`(?i)Server:\s*Microsoft-IIS/([^\s]+)`), Service: "http", VersionGroup: 0},
	{Name: "tomcat", Payload: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"), Regex: regexp.MustCompile(`(?i)Server:\s*Apache-Coyote/([^\s]+)`), Service: "http", VersionGroup: 0},
	{Name: "jetty", Payload: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"), Regex: regexp.MustCompile(`(?i)Server:\s*Jetty\(([^)]+)\)`), Service: "http", VersionGroup: 1},
	{Name: "litespeed", Payload: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"), Regex: regexp.MustCompile(`(?i)Server:\s*LiteSpeed`), Service: "http", VersionGroup: 0},
	{Name: "gunicorn", Payload: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"), Regex: regexp.MustCompile(`(?i)Server:\s*gunicorn/([^\s]+)`), Service: "http", VersionGroup: 0},
	{Name: "werkzeug", Payload: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"), Regex: regexp.MustCompile(`(?i)Server:\s*Werkzeug/([^\s]+)`), Service: "http", VersionGroup: 0},
	{Name: "caddy", Payload: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"), Regex: regexp.MustCompile(`(?i)Server:\s*Caddy`), Service: "http", VersionGroup: 0},
	{Name: "lighttpd", Payload: []byte("GET / HTTP/1.0\r\nHost: localhost\r\n\r\n"), Regex: regexp.MustCompile(`(?i)Server:\s*lighttpd/([^\s]+)`), Service: "http", VersionGroup: 0},

	// ---- 数据库类 ----
	{Name: "mysql", Payload: nil, Regex: regexp.MustCompile(`(?s)^.\x00\x00\x00.\x0a([0-9.]+)`), Service: "mysql", VersionGroup: 1},
	{Name: "mariadb", Payload: nil, Regex: regexp.MustCompile(`(?i)mariadb`), Service: "mysql", VersionGroup: 0},
	{Name: "postgresql", Payload: nil, Regex: regexp.MustCompile(`^[ENSE]`), Service: "postgresql", VersionGroup: 0},
	{Name: "redis", Payload: []byte("PING\r\n"), Regex: regexp.MustCompile(`\+PONG`), Service: "redis", VersionGroup: 0},
	{Name: "redis-auth", Payload: []byte("PING\r\n"), Regex: regexp.MustCompile(`-NOAUTH`), Service: "redis", VersionGroup: 0},
	{Name: "memcached", Payload: []byte("stats\r\n"), Regex: regexp.MustCompile(`STAT version\s+([^\s\r\n]+)`), Service: "memcached", VersionGroup: 1},
	{Name: "mongodb", Payload: nil, Regex: regexp.MustCompile(`(?i)mongodb`), Service: "mongodb", VersionGroup: 0},
	{Name: "elasticsearch", Payload: []byte("GET / HTTP/1.0\r\n\r\n"), Regex: regexp.MustCompile(`(?i)"cluster_name"\s*:\s*"([^"]+)"`), Service: "elasticsearch", VersionGroup: 1},
	{Name: "elasticsearch-version", Payload: []byte("GET / HTTP/1.0\r\n\r\n"), Regex: regexp.MustCompile(`(?i)"number"\s*:\s*"([^"]+)"`), Service: "elasticsearch", VersionGroup: 1},
	{Name: "couchdb", Payload: []byte("GET / HTTP/1.0\r\n\r\n"), Regex: regexp.MustCompile(`(?i)"couchdb"\s*:\s*"([^"]+)"`), Service: "couchdb", VersionGroup: 1},
	{Name: "cassandra", Payload: nil, Regex: regexp.MustCompile(`(?i)cassandra`), Service: "cassandra", VersionGroup: 0},

	// ---- 消息/中间件类 ----
	{Name: "amqp", Payload: []byte("AMQP\x00\x00\x09\x01"), Regex: regexp.MustCompile(`^AMQP`), Service: "amqp", VersionGroup: 0},
	{Name: "mqtt", Payload: nil, Regex: regexp.MustCompile(`^\x20\x02\x00`), Service: "mqtt", VersionGroup: 0},
	{Name: "zookeeper", Payload: []byte("ruok"), Regex: regexp.MustCompile(`imok`), Service: "zookeeper", VersionGroup: 0},
	{Name: "kafka", Payload: nil, Regex: regexp.MustCompile(`(?i)kafka`), Service: "kafka", VersionGroup: 0},

	// ---- 远程桌面/控制类 ----
	{Name: "vnc", Payload: nil, Regex: regexp.MustCompile(`RFB\s+(\d{3}\.\d{3})`), Service: "vnc", VersionGroup: 1},
	{Name: "rdp", Payload: nil, Regex: regexp.MustCompile(`^\x03\x00\x00`), Service: "ms-wbt-server", VersionGroup: 0},

	// ---- 其它 ----
	{Name: "docker", Payload: []byte("GET /v1.24/version HTTP/1.0\r\n\r\n"), Regex: regexp.MustCompile(`(?i)"ApiVersion"\s*:\s*"([^"]+)"`), Service: "docker", VersionGroup: 1},
	{Name: "kubernetes", Payload: []byte("GET /version HTTP/1.0\r\n\r\n"), Regex: regexp.MustCompile(`(?i)"gitVersion"\s*:\s*"([^"]+)"`), Service: "kubernetes", VersionGroup: 1},
	{Name: "irc", Payload: []byte("NICK p\r\nUSER p 0 0 :p\r\n"), Regex: regexp.MustCompile(`(?i):[^\s]+\s+(?:001|002|003|004)\s`), Service: "irc", VersionGroup: 0},
	{Name: "gopher", Payload: []byte("\r\n"), Regex: regexp.MustCompile(`(?i)gopher`), Service: "gopher", VersionGroup: 0},
}

// activeProbePorts 需要发送主动探针的端口(HTTP 类与已知文本协议端口)
// 其它已知服务(如 SMB/RPC/DNS)是二进制协议, 不会应答文本探针, 直接返回端口对应服务名即可
var activeProbePorts = map[int]bool{
	80: true, 443: true, 8080: true, 8081: true, 8000: true, 8008: true,
	8443: true, 8888: true, 3000: true, 5000: true, 7001: true, 9000: true,
	9090: true, 9200: true, 9300: true, 9418: true, 2375: true, 2376: true,
	5984: true, 6443: true, 6379: true, 11211: true, 5672: true, 1883: true,
	2181: true, 7474: true, 9042: true,
}

// detectService 对开放端口进行服务与版本识别
// 返回 (服务名, 版本)
func detectService(ip string, port int, protocol string, timeout time.Duration) (string, string) {
	if protocol != "tcp" {
		return lookupService(port, protocol), ""
	}

	// 服务探测用较短超时, 避免对无应答端口逐个等满超时
	st := timeout
	if st > 700*time.Millisecond {
		st = 700 * time.Millisecond
	}

	banner := ""
	// 先尝试 null 探针(读取服务器主动发送的 banner)
	if b, err := tcpBanner(ip, port, st, nil); err == nil {
		banner = b
	}

	for _, p := range serviceProbes {
		// 跳过需要 payload 的探针(第一阶段只做 null 探针匹配)
		if len(p.Payload) > 0 {
			continue
		}
		if svc, ver, ok := matchProbe(p, banner); ok {
			return svc, ver
		}
	}

	known := lookupService(port, protocol)
	// 已知服务且非主动探针端口: 直接返回服务名, 避免逐个试探浪费时间
	if known != "unknown" && !activeProbePorts[port] {
		return known, ""
	}

	// 第二阶段: 发送主动探针
	for _, p := range serviceProbes {
		if len(p.Payload) == 0 {
			continue
		}
		b, err := tcpBanner(ip, port, st, p.Payload)
		if err != nil {
			continue
		}
		if svc, ver, ok := matchProbe(p, b); ok {
			return svc, ver
		}
	}

	return known, ""
}

func matchProbe(p serviceProbe, data string) (string, string, bool) {
	m := p.Regex.FindStringSubmatch(data)
	if m == nil {
		return "", "", false
	}
	version := ""
	if p.VersionGroup > 0 && p.VersionGroup < len(m) {
		version = m[p.VersionGroup]
	} else if p.VersionGroup == 0 {
		version = m[0]
	}
	return p.Service, cleanVersion(version), true
}

func cleanVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > 64 {
		v = v[:64]
	}
	return v
}
