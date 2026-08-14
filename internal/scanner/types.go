package scanner

import "time"

// ScanType 扫描技术类型
type ScanType string

const (
	ScanTCPConnect ScanType = "tcp-connect" // TCP 全连接扫描
	ScanTCPSYN     ScanType = "tcp-syn"     // TCP SYN 半开扫描
	ScanUDP        ScanType = "udp"         // UDP 扫描
	ScanFIN        ScanType = "fin"         // FIN 扫描
	ScanNULL       ScanType = "null"        // NULL 扫描
	ScanXMAS       ScanType = "xmas"        // Xmas 扫描
	ScanACK        ScanType = "ack"         // ACK 扫描
)

// PortState 端口状态
type PortState string

const (
	StateOpen         PortState = "open"          // 开放
	StateClosed       PortState = "closed"        // 关闭
	StateFiltered     PortState = "filtered"      // 被过滤
	StateOpenFiltered PortState = "open|filtered" // 开放或被过滤
	StateUnfiltered   PortState = "unfiltered"    // 未被过滤
)

// Port 单个端口扫描结果
type Port struct {
	Number   int
	Protocol string // tcp / udp
	State    PortState
	Service  string
	Version  string
}

// OSInfo 操作系统识别结果
type OSInfo struct {
	Name        string
	Family      string
	Confidence  int // 0-100
	TTL         int
	WindowSize  int
	MSS         int
	Details     string
	Fingerprint string
}

// Host 单个主机的完整信息
type Host struct {
	IP       string
	Hostname string
	Up       bool
	Latency  time.Duration
	Ports    []Port
	OS       *OSInfo
}

// Options 扫描配置
type Options struct {
	Targets       []string      // 目标列表
	Ports         string        // 端口表达式, 如 "1-1000" "80,443,8080" "top-100" "-" (全部)
	ExcludePorts  string        // 排除的端口表达式
	ScanTypes     []ScanType    // 扫描技术
	Timeout       time.Duration // 单探测超时
	Concurrency   int           // 并发数
	Rate          int           // 每秒发包数限制, 0 表示不限
	Randomize     bool          // 随机端口顺序
	Timing        int           // 定时模板 0-5
	SkipDiscovery bool          // 跳过主机发现
	DiscoveryOnly bool          // 仅主机发现(不进行端口扫描)
	ServiceDetect bool          // 服务识别
	VersionDetect bool          // 版本识别
	OSDetect      bool          // 操作系统识别
	ResolveDNS    bool          // 反向 DNS 解析
	Verbose       bool          // 详细输出
	ProxyURL      string        // 代理地址, 如 socks5://127.0.0.1:1080 或 http://127.0.0.1:8080
	StopAfterHost bool          // 命中第一个存活主机/开放端口后立即停止
	MaxTargets    int           // 目标数量上限, 防止误扫大网段(默认 10000)
	POC           bool          // 高危端口未授权访问检测
	Fingerprint   bool          // CMS/Web 指纹识别
	ForceRaw      bool          // 强制使用 raw socket(覆盖 proot 安全降级)
}

// Result 实时扫描结果(用于进度回调/界面刷新)
type Result struct {
	IP       string        `json:"ip" xml:"ip,attr"`
	Hostname string        `json:"hostname,omitempty" xml:"hostname,attr,omitempty"`
	Port     int           `json:"port" xml:"port,attr"`
	Protocol string        `json:"protocol" xml:"protocol,attr"`
	State    PortState     `json:"state" xml:"state,attr"`
	Service  string        `json:"service" xml:"service,attr"`
	Version  string        `json:"version,omitempty" xml:"version,attr,omitempty"`
	OS       string        `json:"os,omitempty" xml:"os,attr,omitempty"`
	Vuln     string        `json:"vuln,omitempty" xml:"vuln,attr,omitempty"`
	Latency  time.Duration `json:"-" xml:"-"`
	Err      string        `json:"error,omitempty" xml:"error,attr,omitempty"`
}

// Progress 进度信息
type Progress struct {
	TotalHosts  int
	ScannedHost int
	TotalPorts  int
	ScannedPort int
	Percent     float64
	Message     string
}

// DefaultOptions 返回默认扫描配置
func DefaultOptions() Options {
	return Options{
		Ports:         "1-65535",
		ScanTypes:     []ScanType{ScanTCPSYN, ScanTCPConnect},
		Timeout:       time.Second,
		Concurrency:   500,
		Timing:        3,
		SkipDiscovery: false,
		ServiceDetect: true,
		VersionDetect: true,
		OSDetect:      true,
		ResolveDNS:    false,
		Verbose:       false,
		MaxTargets:    10000,
	}
}
