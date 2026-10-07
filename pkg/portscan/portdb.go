package portscan

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

// commonPorts 常见端口 -> 服务名映射(依据 IANA 服务名注册表与业界通用端口约定整理)
var commonPorts = map[int]portInfo{
	1:     {"tcpmux", ""},
	3:     {"compressnet", ""},
	7:     {"echo", ""},
	9:     {"discard", ""},
	13:    {"daytime", ""},
	17:    {"qotd", ""},
	19:    {"chargen", ""},
	20:    {"ftp-data", ""},
	21:    {"ftp", "文件传输协议"},
	22:    {"ssh", "安全外壳"},
	23:    {"telnet", "远程登录"},
	24:    {"priv-mail", ""},
	25:    {"smtp", "简单邮件传输"},
	26:    {"rsftp", ""},
	33:    {"dsp", ""},
	37:    {"time", ""},
	42:    {"nameserver", ""},
	53:    {"domain", "DNS 域名解析"},
	69:    {"tftp", "简单文件传输"},
	79:    {"finger", ""},
	80:    {"http", "超文本传输"},
	81:    {"hosts2-ns", ""},
	82:    {"xfer", ""},
	88:    {"kerberos-sec", "Kerberos"},
	100:   {"newacct", ""},
	106:   {"pop3pw", ""},
	110:   {"pop3", "邮局协议 v3"},
	111:   {"rpcbind", "RPC 绑定"},
	113:   {"ident", "认证服务"},
	119:   {"nntp", "网络新闻传输"},
	123:   {"ntp", "网络时间协议"},
	135:   {"msrpc", "微软 RPC"},
	139:   {"netbios-ssn", "NetBIOS 会话"},
	143:   {"imap", "互联网消息访问"},
	144:   {"news", ""},
	161:   {"snmp", "简单网络管理"},
	162:   {"snmptrap", "SNMP 陷阱"},
	179:   {"bgp", "边界网关协议"},
	199:   {"smux", ""},
	222:   {"rsh-spx", ""},
	264:   {"bgmp", ""},
	280:   {"http-mgmt", ""},
	311:   {"asip-webadmin", ""},
	366:   {"odmr", ""},
	389:   {"ldap", "轻量目录访问"},
	407:   {"timbuktu", ""},
	427:   {"svrloc", ""},
	443:   {"https", "安全超文本传输"},
	444:   {"snpp", ""},
	445:   {"microsoft-ds", "SMB 文件共享"},
	464:   {"kpasswd5", "Kerberos 改密"},
	465:   {"smtps", "SMTPS"},
	497:   {"retrospect", ""},
	500:   {"isakmp", "IPSec 密钥协商"},
	512:   {"exec", ""},
	513:   {"login", ""},
	514:   {"shell", "syslog/远程命令"},
	515:   {"printer", "行式打印机"},
	543:   {"klogin", ""},
	544:   {"kshell", ""},
	548:   {"afp", "苹果文件协议"},
	554:   {"rtsp", "实时流协议"},
	563:   {"snews", ""},
	587:   {"submission", "邮件提交"},
	593:   {"http-rpc-epmap", ""},
	625:   {"apple-xsrvr-admin", ""},
	631:   {"ipp", "互联网打印协议"},
	636:   {"ldapssl", "安全 LDAP"},
	646:   {"ldp", ""},
	787:   {"qsc", ""},
	808:   {"ccproxy-http", ""},
	873:   {"rsync", "远程同步"},
	888:   {"accessbuilder", ""},
	902:   {"iss-realsecure", ""},
	990:   {"ftps", ""},
	992:   {"telnets", ""},
	999:   {"garcon", ""},
	1000:  {"cadlock", ""},
	1022:  {"exp2", ""},
	1023:  {"netvenuechat", ""},
	1024:  {"kdm", ""},
	1027:  {"IIS", ""},
	1029:  {"ms-lsa", ""},
	1030:  {"iad1", ""},
	1031:  {"iad2", ""},
	1032:  {"iad3", ""},
	1033:  {"netinfo", ""},
	1034:  {"zincite-a", ""},
	1035:  {"multidropper", ""},
	1036:  {"nsstp", ""},
	1037:  {"ams", ""},
	1038:  {"mtqp", ""},
	1039:  {"sbl", ""},
	1040:  {"netsaint", ""},
	1041:  {"danf-ak2", ""},
	1042:  {"afrog", ""},
	1043:  {"boinc", ""},
	1044:  {"dcutility", ""},
	1047:  {"neod1", ""},
	1048:  {"neod2", ""},
	1049:  {"td-postman", ""},
	1051:  {"optima-vnet", ""},
	1052:  {"ddt", ""},
	1053:  {"remote-as", ""},
	1054:  {"brvread", ""},
	1055:  {"ansyslmd", ""},
	1058:  {"nim", ""},
	1059:  {"nimreg", ""},
	1060:  {"polestar", ""},
	1062:  {"veracity", ""},
	1064:  {"jstel", ""},
	1065:  {"syscomlan", ""},
	1066:  {"fpo-fns", ""},
	1067:  {"instl_boots", ""},
	1068:  {"instl_bootc", ""},
	1069:  {"cognex-insight", ""},
	1071:  {"bsquare-voip", ""},
	1074:  {"warmspotMgmt", ""},
	1080:  {"socks", "SOCKS 代理"},
	1110:  {"nfsd-status", ""},
	1111:  {"lmsocialserver", ""},
	1218:  {"aeroflight-ads", ""},
	1234:  {"hotline", ""},
	1311:  {"rxmon", ""},
	1352:  {"lotusnotes", "Lotus Notes"},
	1433:  {"ms-sql-s", "微软 SQL Server"},
	1494:  {"citrix-ica", "Citrix"},
	1521:  {"oracle", "Oracle 数据库"},
	1700:  {"mps-raft", ""},
	1717:  {"fj-hdnet", ""},
	1720:  {"h323q931", ""},
	1723:  {"pptp", "点对点隧道协议"},
	1755:  {"wms", ""},
	1761:  {"landesk-rc", ""},
	1801:  {"msmq", ""},
	1883:  {"mqtt", "MQTT 消息队列"},
	1900:  {"upnp", "UPnP 发现"},
	1935:  {"rtmp", ""},
	1998:  {"x25-svc-port", ""},
	2000:  {"cisco-sccp", ""},
	2001:  {"dc", ""},
	2002:  {"globe", ""},
	2003:  {"finger", ""},
	2004:  {"mailbox", ""},
	2005:  {"deslogin", ""},
	2006:  {"invokator", ""},
	2007:  {"dectalk", ""},
	2008:  {"conf", ""},
	2009:  {"news", ""},
	2010:  {"search", ""},
	2049:  {"nfs", "网络文件系统"},
	2065:  {"dlsrpn", ""},
	2103:  {"zephyr-clt", ""},
	2105:  {"eklogin", ""},
	2107:  {"msmq-mgmt", ""},
	2121:  {"ccproxy-ftp", ""},
	2161:  {"apc-agent", ""},
	2181:  {"zookeeper", "ZooKeeper"},
	2301:  {"compaqdiag", ""},
	2375:  {"docker", "Docker REST API"},
	2379:  {"etcd", "etcd"},
	2383:  {"ms-olap4", ""},
	2401:  {"cvspserver", "CVS"},
	2601:  {"zebra", ""},
	2602:  {"ripd", ""},
	2604:  {"ospfd", ""},
	2701:  {"sms-rcinfo", ""},
	2702:  {"sms-xfer", ""},
	2717:  {"pn-requester", ""},
	2869:  {"icslap", ""},
	2967:  {"symantec-av", ""},
	3000:  {"http-alt", "开发服务器/Node"},
	3001:  {"nessus", "Nessus"},
	3052:  {"powerchute", ""},
	3128:  {"squid-http", "Squid 代理"},
	3260:  {"iscsi", "iSCSI"},
	3268:  {"globalcatLDAP", ""},
	3269:  {"globalcatLDAPssl", ""},
	3283:  {"netassistant", ""},
	3306:  {"mysql", "MySQL 数据库"},
	3333:  {"dec-notes", ""},
	3389:  {"ms-wbt-server", "远程桌面 RDP"},
	3689:  {"rendezvous", ""},
	3690:  {"svn", "Subversion"},
	3703:  {"adobeserver-3", ""},
	3986:  {"mapper-ws_ethd", ""},
	4000:  {"remoteanything", ""},
	4001:  {"newoak", ""},
	4002:  {"mlchat-proxy", ""},
	4045:  {"lockd", ""},
	4443:  {"pharos", ""},
	4444:  {"krb524", ""},
	4662:  {"edonkey", ""},
	4899:  {"radmin", ""},
	5000:  {"http-alt", "Flask/UPnP"},
	5001:  {"commplex-link", ""},
	5002:  {"rfe", ""},
	5003:  {"filemaker", ""},
	5009:  {"airport-admin", ""},
	5050:  {"mmcc", ""},
	5051:  {"ida-agent", ""},
	5060:  {"sip", "SIP"},
	5100:  {"admd", ""},
	5101:  {"admdog", ""},
	5120:  {"barracuda-bbs", ""},
	5190:  {"aol", ""},
	5225:  {"hp-server", ""},
	5226:  {"hp-status", ""},
	5357:  {"wsdapi", ""},
	5432:  {"postgresql", "PostgreSQL 数据库"},
	5550:  {"sdadmind", ""},
	5555:  {"personal-agent", ""},
	5601:  {"kibana", "Kibana"},
	5631:  {"pcanywheredata", ""},
	5666:  {"nrpe", "Nagios NRPE"},
	5672:  {"amqp", "RabbitMQ"},
	5800:  {"vnc-http", "VNC HTTP"},
	5801:  {"vnc-http-1", "VNC HTTP"},
	5900:  {"vnc", "VNC 远程控制"},
	5901:  {"vnc-1", "VNC 显示 1"},
	5902:  {"vnc-2", "VNC 显示 2"},
	5984:  {"couchdb", "CouchDB"},
	6000:  {"X11", "X11"},
	6112:  {"dtspc", ""},
	6379:  {"redis", "Redis 数据库"},
	6443:  {"kubernetes", "Kubernetes API"},
	6543:  {"mythtv", ""},
	6666:  {"irc", "IRC"},
	6789:  {"ibm-db2-admin", ""},
	7000:  {"afs3-fileserver", ""},
	7001:  {"afs3-callback", "WebLogic"},
	7019:  {"doceri-ctl", ""},
	7070:  {"realserver", ""},
	7100:  {"font-service", ""},
	7474:  {"neo4j", "Neo4j 图数据库"},
	7937:  {"nsrexecd", ""},
	7938:  {"lgtomapper", ""},
	8000:  {"http-alt", "HTTP 备用"},
	8002:  {"teradataordbms", ""},
	8008:  {"http-alt", "HTTP 备用"},
	8009:  {"ajp13", "AJP 连接器"},
	8010:  {"xmpp", ""},
	8080:  {"http-proxy", "HTTP 代理/备用"},
	8081:  {"http-proxy", "HTTP 代理/备用"},
	8082:  {"blackice-alerts", ""},
	8088:  {"hadoop-yarn", "Hadoop YARN"},
	8192:  {"sophos", ""},
	8193:  {"sophos", ""},
	8194:  {"sophos", ""},
	8443:  {"https-alt", "HTTPS 备用"},
	8500:  {"consul", "Consul"},
	8848:  {"nacos", "Nacos"},
	8888:  {"http-alt", "HTTP 备用"},
	9000:  {"http-alt", "SonarQube/开发"},
	9001:  {"tor-orport", "Tor"},
	9042:  {"cassandra", "Cassandra"},
	9050:  {"tor-socks", "Tor"},
	9090:  {"http-alt", "Prometheus/Web"},
	9100:  {"jetdirect", "打印机"},
	9102:  {"jetdirect", ""},
	9200:  {"elasticsearch", "Elasticsearch"},
	9418:  {"git", "Git 协议"},
	9535:  {"man", ""},
	9593:  {"cba8", ""},
	9594:  {"msgsys", ""},
	9595:  {"pds", ""},
	9999:  {"abyss", ""},
	10000: {"snet-sensor-mgmt", "Webmin"},
	10001: {"scp-config", ""},
	10010: {"rxapi", ""},
	11211: {"memcached", "Memcached"},
	13782: {"netbackup", ""},
	15000: {"hydap", ""},
	16992: {"amt-soap-http", ""},
	16993: {"amt-soap-https", ""},
	27017: {"mongodb", "MongoDB 数据库"},
	32768: {"filenet-tms", ""},
	32769: {"filenet-rpc", ""},
	42510: {"caerpc", ""},
	50000: {"ibm-db2", ""},
	50070: {"hdfs", "HDFS NameNode"},
	61616: {"activemq", "ActiveMQ"},
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
