package scanner

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// pocProbe 高危服务未授权访问探测项
type pocProbe struct {
	Service string
	Port    int
	Payload []byte // 原始 socket 探测 payload(nil 表示不发送直接读)
	HTTP    bool   // 使用 HTTP GET 探测
	Path    string // HTTP 路径
	Match   func(string) bool
	Vuln    string
}

// pocProbes 高危服务探测表(每个探测只发 1-2 个包)
var pocProbes = []pocProbe{
	{
		Service: "redis", Port: 6379,
		Payload: []byte("INFO\r\n"),
		Match:   func(r string) bool { return strings.Contains(r, "redis_version") },
		Vuln:    "Redis 未授权访问(INFO 可执行, 可被写文件/提权)",
	},
	{
		Service: "mongodb", Port: 27017,
		Payload: mongoIsMaster(),
		Match:   func(r string) bool { return strings.Contains(r, "ismaster") || strings.Contains(r, "maxWireVersion") },
		Vuln:    "MongoDB 未授权访问(isMaster 可执行, 数据库可被读写)",
	},
	{
		Service: "memcached", Port: 11211,
		Payload: []byte("stats\r\n"),
		Match:   func(r string) bool { return strings.Contains(r, "STAT") },
		Vuln:    "Memcached 未授权访问(stats 可执行, 数据可被读取/篡改)",
	},
	{
		Service: "zookeeper", Port: 2181,
		Payload: []byte("ruok"),
		Match:   func(r string) bool { return strings.Contains(r, "imok") },
		Vuln:    "ZooKeeper 未授权访问(ruok 可执行)",
	},
	{
		Service: "elasticsearch", Port: 9200,
		HTTP: true, Path: "/",
		Match: func(r string) bool {
			return strings.Contains(r, "cluster_name") || strings.Contains(r, "version")
		},
		Vuln: "Elasticsearch 未授权访问(可读取集群信息/数据)",
	},
	{
		Service: "docker", Port: 2375,
		HTTP: true, Path: "/version",
		Match: func(r string) bool { return strings.Contains(r, "ApiVersion") },
		Vuln:  "Docker API 未授权访问(可执行容器/读取宿主机)",
	},
	{
		Service: "docker", Port: 2376,
		HTTP: true, Path: "/version",
		Match: func(r string) bool { return strings.Contains(r, "ApiVersion") },
		Vuln:  "Docker API 未授权访问(可执行容器/读取宿主机)",
	},
	{
		Service: "couchdb", Port: 5984,
		HTTP: true, Path: "/",
		Match: func(r string) bool { return strings.Contains(r, "couchdb") },
		Vuln:  "CouchDB 未授权访问(可读取数据库)",
	},
	{
		Service: "etcd", Port: 2379,
		HTTP: true, Path: "/version",
		Match: func(r string) bool { return strings.Contains(r, "etcdserver") || strings.Contains(r, "etcdcluster") },
		Vuln:  "etcd 未授权访问(可读写键值对)",
	},
	{
		Service: "consul", Port: 8500,
		HTTP: true, Path: "/v1/agent/self",
		Match: func(r string) bool { return strings.Contains(r, "Config") || strings.Contains(r, "Member") },
		Vuln:  "Consul 未授权访问(可读取服务注册信息)",
	},
	{
		Service: "nacos", Port: 8848,
		HTTP: true, Path: "/nacos/v1/auth/users?pageNo=1&pageSize=9",
		Match: func(r string) bool { return strings.Contains(r, "totalCount") || strings.Contains(r, "username") },
		Vuln:  "Nacos 未授权访问(可读取用户列表/配置)",
	},
	{
		Service: "jenkins", Port: 8080,
		HTTP: true, Path: "/script",
		Match: func(r string) bool { return strings.Contains(r, "Jenkins") },
		Vuln:  "Jenkins 疑似未授权(可访问脚本控制台)",
	},
	{
		Service: "jenkins", Port: 8090,
		HTTP: true, Path: "/script",
		Match: func(r string) bool { return strings.Contains(r, "Jenkins") },
		Vuln:  "Jenkins 疑似未授权(可访问脚本控制台)",
	},
	{
		Service: "hadoop", Port: 8088,
		HTTP: true, Path: "/cluster",
		Match: func(r string) bool { return strings.Contains(r, "cluster") || strings.Contains(r, "ResourceManager") },
		Vuln:  "Hadoop YARN 未授权访问(可提交任务/执行代码)",
	},
}

// mongoIsMaster 构造 MongoDB isMaster 探测报文
func mongoIsMaster() []byte {
	bson := []byte{
		0x13, 0x00, 0x00, 0x00, // 文档长度 19(4 头 + 1 类型 + 9 键名 + 4 值 + 1 结束)
		0x10,                                         // int32 类型
		'i', 's', 'm', 'a', 's', 't', 'e', 'r', 0x00, // "ismaster\0"
		0x01, 0x00, 0x00, 0x00, // 值 1
		0x00, // 结束符
	}
	coll := append([]byte("admin.$cmd"), 0x00)
	msgLen := 16 + 4 + len(coll) + 8 + len(bson) // 16 头 + 4 flags + coll + 4 skip + 4 return + bson
	msg := make([]byte, 0, msgLen)
	var b4 [4]byte
	put := func(v int32) {
		binary.LittleEndian.PutUint32(b4[:], uint32(v))
		msg = append(msg, b4[:]...)
	}
	put(int32(msgLen))
	put(1)    // requestID
	put(0)    // responseTo
	put(2004) // OP_QUERY
	put(0)    // flags
	msg = append(msg, coll...)
	put(0)  // numberToSkip
	put(-1) // numberToReturn
	msg = append(msg, bson...)
	return msg
}

// RunPOC 检测单个开放端口是否存在未授权访问, 返回漏洞描述(空表示未发现)
func RunPOC(ip string, port int, timeout time.Duration) string {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	for _, p := range pocProbes {
		if p.Port != port {
			continue
		}
		if p.HTTP {
			// HTTP 探测要求 200, 避免 403/401 错误页含关键词造成误报
			resp, status := httpDo(ip, port, "GET", p.Path, "", "", timeout)
			if status != 200 {
				continue
			}
			if p.Match(resp) {
				return p.Vuln
			}
		} else {
			resp, err := rawProbe(ip, port, p.Payload, timeout)
			if err == nil && p.Match(resp) {
				return p.Vuln
			}
		}
	}
	return ""
}

func rawProbe(ip string, port int, payload []byte, timeout time.Duration) (string, error) {
	conn, err := dialTimeout(net.JoinHostPort(ip, itoa(port)), timeout)
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

func httpGet(ip string, port int, path string, timeout time.Duration) (string, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := fmt.Sprintf("http://%s%s", net.JoinHostPort(ip, itoa(port)), path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "NetScan/2.0 poc")
	resp, err := httpClient(timeout).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	return string(b), nil
}
