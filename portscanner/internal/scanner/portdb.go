package scanner

import (
	"sort"
	"strconv"
	"strings"
)

// portInfo 端口与服务对应关系
type portInfo struct {
	Service string
	Desc    string
}

// commonPorts 常见端口 -> 服务名映射(精简但覆盖主流服务)
var commonPorts = map[int]portInfo{
	21:   {"ftp", "文件传输协议"},
	22:   {"ssh", "安全外壳"},
	23:   {"telnet", "远程登录"},
	25:   {"smtp", "简单邮件传输"},
	53:   {"domain", "DNS 域名解析"},
	67:   {"dhcps", "DHCP 服务端"},
	68:   {"dhcpc", "DHCP 客户端"},
	69:   {"tftp", "简单文件传输"},
	80:   {"http", "超文本传输"},
	110:  {"pop3", "邮局协议 v3"},
	111:  {"rpcbind", "RPC 绑定"},
	123:  {"ntp", "网络时间协议"},
	135:  {"msrpc", "微软 RPC"},
	137:  {"netbios-ns", "NetBIOS 名称服务"},
	138:  {"netbios-dgm", "NetBIOS 数据报"},
	139:  {"netbios-ssn", "NetBIOS 会话"},
	143:  {"imap", "互联网消息访问"},
	161:  {"snmp", "简单网络管理"},
	162:  {"snmptrap", "SNMP 陷阱"},
	179:  {"bgp", "边界网关协议"},
	389:  {"ldap", "轻量目录访问"},
	443:  {"https", "安全超文本传输"},
	445:  {"microsoft-ds", "SMB 文件共享"},
	465:  {"smtps", "SMTPS"},
	500:  {"isakmp", "IPSec 密钥协商"},
	514:  {"syslog", "系统日志"},
	515:  {"printer", "行式打印机"},
	548:  {"afp", "苹果文件协议"},
	554:  {"rtsp", "实时流协议"},
	587:  {"submission", "邮件提交"},
	631:  {"ipp", "互联网打印协议"},
	636:  {"ldaps", "安全 LDAP"},
	873:  {"rsync", "远程同步"},
	902:  {"vmware-auth", "VMware 认证"},
	993:  {"imaps", "安全 IMAP"},
	995:  {"pop3s", "安全 POP3"},
	1080: {"socks", "SOCKS 代理"},
	1194: {"openvpn", "OpenVPN"},
	1433: {"ms-sql-s", "微软 SQL Server"},
	1521: {"oracle", "Oracle 数据库"},
	1723: {"pptp", "点对点隧道协议"},
	1883: {"mqtt", "MQTT 消息队列"},
	1900: {"upnp", "UPnP 发现"},
	2049: {"nfs", "网络文件系统"},
	2181: {"zookeeper", "ZooKeeper"},
	2375: {"docker", "Docker REST API"},
	2376: {"docker-s", "Docker TLS API"},
	3000: {"http-alt", "开发服务器/Node"},
	3128: {"squid-http", "Squid 代理"},
	3306: {"mysql", "MySQL 数据库"},
	3389: {"ms-wbt-server", "远程桌面 RDP"},
	3690: {"svn", "Subversion"},
	4369: {"epmd", "Erlang 端口映射"},
	4443: {"http", "HTTPS 备用"},
	4567: {"http", "Sinatra"},
	5000: {"http", "Flask/UPnP"},
	5432: {"postgresql", "PostgreSQL 数据库"},
	5672: {"amqp", "RabbitMQ"},
	5900: {"vnc", "VNC 远程控制"},
	5901: {"vnc-1", "VNC 显示 1"},
	5984: {"couchdb", "CouchDB"},
	5985: {"wsman", "WinRM HTTP"},
	5986: {"wsmans", "WinRM HTTPS"},
	6379: {"redis", "Redis 数据库"},
	6443: {"kubernetes", "Kubernetes API"},
	7001: {"http", "WebLogic"},
	7474: {"neo4j", "Neo4j 图数据库"},
	8000: {"http-alt", "HTTP 备用"},
	8008: {"http-alt", "HTTP 备用"},
	8009: {"ajp13", "AJP 连接器"},
	8080: {"http-proxy", "HTTP 代理/备用"},
	8081: {"http-proxy", "HTTP 代理/备用"},
	8443: {"https-alt", "HTTPS 备用"},
	8888: {"http-alt", "HTTP 备用"},
	9000: {"http-alt", "SonarQube/开发"},
	9042: {"cassandra", "Cassandra"},
	9090: {"http-alt", "Prometheus/Web"},
	9200: {"http-alt", "Elasticsearch"},
	9300: {"http-alt", "Elasticsearch 节点"},
	9418: {"git", "Git 协议"},
	10000:{"webmin", "Webmin"},
	11211:{"memcached", "Memcached"},
	15672:{"amqp-mgmt", "RabbitMQ 管理"},
	27017:{"mongodb", "MongoDB 数据库"},
	27018:{"mongodb", "MongoDB"},
	28017:{"mongodb", "MongoDB Web"},
	50070:{"hdfs", "HDFS NameNode"},
	61616:{"activemq", "ActiveMQ"},
}

// portByName 从服务名反查端口
func portByName() map[string]int {
	m := map[string]int{}
	for p, info := range commonPorts {
		if _, ok := m[info.Service]; !ok {
			m[info.Service] = p
		}
	}
	return m
}

// lookupService 查询端口对应服务名
func lookupService(port int, protocol string) string {
	if info, ok := commonPorts[port]; ok {
		if port == 53 && protocol == "tcp" {
			return "domain"
		}
		return info.Service
	}
	return "unknown"
}

// topPorts 按常见度排序的端口列表(用于 "top-N")
var topPorts = []int{
	80, 23, 443, 21, 22, 25, 3389, 110, 445, 139,
	143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900,
	1025, 587, 8888, 199, 1720, 465, 548, 113, 81, 6001,
	10000, 514, 5060, 179, 1026, 2000, 8443, 8000, 32768, 554,
	26, 1433, 49152, 2001, 515, 8008, 49154, 1027, 5666, 646,
	5000, 5631, 631, 49153, 8081, 2049, 88, 79, 5800, 106,
	2121, 1110, 49155, 6000, 513, 990, 5357, 427, 49156, 543,
	544, 5101, 144, 7, 389, 8009, 3128, 444, 9999, 5009,
	7070, 5190, 3000, 5432, 1900, 3986, 13, 1029, 9, 5051,
	6646, 49157, 1028, 873, 1755, 2717, 4899, 9100, 119, 37,
}

// parsePortSpec 解析端口表达式, 返回端口列表
// 支持: "80" "1-1000" "80,443,8080" "top-100" "top-1000" "-"(全部1-65535) 组合 "22,80-90,443"
func parsePortSpec(spec string) []int {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		spec = "top-1000"
	}
	ports := map[int]bool{}

	parts := strings.Split(spec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lower := strings.ToLower(part)
		switch {
		case lower == "-" || lower == "all" || lower == "1-65535":
			for i := 1; i <= 65535; i++ {
				ports[i] = true
			}
		case strings.HasPrefix(lower, "top-"):
			n, err := strconv.Atoi(strings.TrimPrefix(lower, "top-"))
			if err != nil || n <= 0 {
				n = 100
			}
			if n > len(topPorts) {
				n = len(topPorts)
			}
			for i := 0; i < n; i++ {
				ports[topPorts[i]] = true
			}
		case strings.Contains(part, "-"):
			bounds := strings.SplitN(part, "-", 2)
			lo, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			hi, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil {
				continue
			}
			if lo < 1 {
				lo = 1
			}
			if hi > 65535 {
				hi = 65535
			}
			if lo > hi {
				lo, hi = hi, lo
			}
			for i := lo; i <= hi; i++ {
				ports[i] = true
			}
		default:
			if p, err := strconv.Atoi(part); err == nil && p >= 1 && p <= 65535 {
				ports[p] = true
			} else if svcPort, ok := portByName()[lower]; ok {
				ports[svcPort] = true
			}
		}
	}

	out := make([]int, 0, len(ports))
	for p := range ports {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}
