// Package scanner 兼容门面: 保留原有 scanner.* API, 内部已按领域拆分到子包。
//
// 领域划分:
//   - pkg/portscan      主机发现/端口扫描/服务识别/OS 识别(不依赖利用库与 SQLite)
//   - internal/netx     网络与基础原语(代理/HTTP/限速/受限并发/路径)
//   - internal/webscan  目录爆破/子域名/HTTP 头/CMS 指纹/Whois/DNS
//   - internal/poc      nuclei 模板引擎 + 内置模板 + 未授权 POC
//   - internal/exploit  漏洞库/主动利用/爆破/一键拿 shell/shell 链
//   - internal/store    SQLite 资产库 + 监控状态
//   - internal/plugin   插件系统与远程市场
//   - internal/report   HTML 报告
//
// 新代码建议直接引用具体子包; 外部模块若只需端口扫描能力, 引用 pkg/portscan 即可,
// 不会连带引入 modernc.org/sqlite 与利用库。
package scanner

import (
	"strings"
	"time"

	"portscanner/internal/exploit"
	"portscanner/internal/netx"
	"portscanner/internal/plugin"
	"portscanner/internal/poc"
	"portscanner/internal/report"
	"portscanner/internal/store"
	"portscanner/internal/webscan"
	"portscanner/pkg/portscan"
)

// ---- 核心扫描(pkg/portscan) ----

type (
	Options   = portscan.Options
	Result    = portscan.Result
	Progress  = portscan.Progress
	Scanner   = portscan.Scanner
	ScanType  = portscan.ScanType
	Port      = portscan.Port
	Host      = portscan.Host
	PortState = portscan.PortState
	OSInfo    = portscan.OSInfo
)

const (
	ScanTCPConnect = portscan.ScanTCPConnect
	ScanTCPSYN     = portscan.ScanTCPSYN
	ScanUDP        = portscan.ScanUDP
	ScanFIN        = portscan.ScanFIN
	ScanNULL       = portscan.ScanNULL
	ScanXMAS       = portscan.ScanXMAS
	ScanACK        = portscan.ScanACK

	StateOpen         = portscan.StateOpen
	StateClosed       = portscan.StateClosed
	StateFiltered     = portscan.StateFiltered
	StateOpenFiltered = portscan.StateOpenFiltered
	StateUnfiltered   = portscan.StateUnfiltered
)

var (
	DefaultOptions = portscan.DefaultOptions
	Ping           = portscan.Ping
	PingAny        = portscan.PingAny
	TraceRoute     = portscan.TraceRoute
	GrabBanner     = portscan.GrabBanner
)

// NewScanner 创建扫描器。POC 检测与 CMS 指纹属于上层能力,
// 这里通过结果回调补充(与拆分前的行为一致), 使扫描核心与利用库解耦。
func NewScanner(opts portscan.Options, onResult func(portscan.Result), onProgress func(portscan.Progress)) *portscan.Scanner {
	var sc *portscan.Scanner
	if onResult != nil && (opts.POC || opts.Fingerprint) {
		user := onResult
		onResult = func(r portscan.Result) {
			if r.State == portscan.StateOpen {
				if opts.POC {
					hits := poc.ScanPOCs(r.IP, r.Port, sc.Timeout())
					if len(hits) > 0 {
						ids := make([]string, 0, len(hits))
						for _, h := range hits {
							if f := strings.Fields(h.Name); len(f) > 0 {
								ids = append(ids, f[0])
							}
						}
						r.Vuln = strings.Join(ids, ", ")
					}
				}
				if opts.Fingerprint && r.Protocol == "tcp" && portscan.IsHTTPService(r.Service) {
					https := r.Service == "https" || r.Service == "https-alt" || r.Port == 443 || r.Port == 8443
					if fp := webscan.Fingerprint(r.IP, r.Port, https, 2*time.Second); fp != "" {
						r.Service = fp
						r.Version = ""
					}
				}
			}
			user(r)
		}
	}
	sc = portscan.NewScanner(opts, onResult, onProgress)
	return sc
}

// ---- Web 侦察(internal/webscan) ----

var (
	DirSearch      = webscan.DirSearch
	SubdomainBrute = webscan.SubdomainBrute
	WebHeaderCheck = webscan.WebHeaderCheck
	Fingerprint    = webscan.Fingerprint
	Whois          = webscan.Whois
	DNSRecords     = webscan.DNSRecords
)

// ---- POC(internal/poc) ----

// POCBuiltinList 内置模板摘要(id/name 过滤, limit<=0 不限制)
func POCBuiltinList(filter string, limit int) []poc.BuiltinPOCInfo {
	return poc.BuiltinPOCList(filter, limit)
}

// ScanPOCsFilteredLimit 按过滤条件运行最多 limit 条内置 POC 模板
func ScanPOCsFilteredLimit(ip string, port int, timeout time.Duration, filter string, limit int) []poc.VulnHit {
	return poc.ScanPOCsFilteredLimit(ip, port, timeout, filter, limit)
}

type (
	VulnHit     = poc.VulnHit
	POCTemplate = poc.POCTemplate
	POCRequest  = poc.POCRequest
	POCResponse = poc.POCResponse
	POCMatcher  = poc.POCMatcher
	POCManager  = poc.POCManager
)

var (
	DefaultPOCDir   = poc.DefaultPOCDir
	OpenPOCManager  = poc.OpenPOCManager
	LoadPOCTemplate = poc.LoadPOCTemplate
	RunPOC          = poc.RunPOC
)

// ScanPOCs 批量扫描 Web POC(内置 nuclei 模板 + 用户自定义 + 插件 POC)
func ScanPOCs(ip string, port int, timeout time.Duration) []poc.VulnHit {
	return poc.ScanPOCs(ip, port, timeout, plugin.OpenPluginManager("").POCs())
}

// ScanPOCsFiltered 仅运行 id/name 匹配 filter 的内置 POC(定向验证用)
func ScanPOCsFiltered(ip string, port int, timeout time.Duration, filter string) []poc.VulnHit {
	return poc.ScanPOCsFiltered(ip, port, timeout, filter)
}

// ---- 漏洞利用(internal/exploit) ----

type (
	BruteResult       = exploit.BruteResult
	ExploitModule     = exploit.ExploitModule
	DictManager       = exploit.DictManager
	ModuleManager     = exploit.ModuleManager
	ShellChainManager = exploit.ShellChainManager
)

var (
	AutoExploit           = exploit.AutoExploit
	BruteForce            = exploit.BruteForce
	BruteSSHOnce          = exploit.BruteSSHOnce
	DefaultDictDir        = exploit.DefaultDictDir
	ExploitList           = exploit.ExploitList
	GetShell              = exploit.GetShell
	OpenDictManager       = exploit.OpenDictManager
	OpenModuleManager     = exploit.OpenModuleManager
	OpenShellChainManager = exploit.OpenShellChainManager
	ReverseShell          = exploit.ReverseShell
	RunExploit            = exploit.RunExploit
	RunExploitChain       = exploit.RunChain
	ExploitChainList      = exploit.ChainList
	ScanVulns             = exploit.ScanVulns
	ShellTypeList         = exploit.ShellTypeList
	SSHInteractive        = exploit.SSHInteractive
	VulnReport            = exploit.VulnReport
)

// ---- 存储(internal/store) ----

type Store = store.Store

var (
	OpenStore       = store.OpenStore
	DefaultStateDir = store.DefaultStateDir
	DiffState       = store.DiffState
)

// ---- 插件(internal/plugin) ----

type PluginManager = plugin.PluginManager

var (
	DefaultPluginDir    = plugin.DefaultPluginDir
	OpenPluginManager   = plugin.OpenPluginManager
	InstallMarketPlugin = plugin.InstallMarketPlugin
	MarketplacePlugins  = plugin.MarketplacePlugins
	SetMarketURL        = plugin.SetMarketURL
)

// ---- 报告(internal/report) ----

var WriteHTMLReport = report.WriteHTMLReport

// ---- 字典(webscan) ----

// DefaultDirWordlist 内置目录/文件爆破字典副本
func DefaultDirWordlist() []string { return webscan.DefaultDirWordlist() }

// SetPOCDebug 设置 POC 引擎调试输出钩子(CLI --poc-debug)
func SetPOCDebug(f func(string, ...interface{})) { poc.SetDebug(f) }

// ---- OAST 回调(netx) ----

// StartOAST 启动内置 HTTP 回调监听(SSRF/RCE 外带检测),
// advertise 为目标可达的 host:port(端口 0 表示随机)。
func StartOAST(advertise string) error { return netx.StartOAST(advertise) }
