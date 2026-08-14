package main

import (
	"encoding/json"
	"encoding/xml"
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"portscanner/internal/scanner"
)

const version = "1.2.0"

type cliFlags struct {
	targets      string
	ports        string
	excludePorts string
	sT, sS, sU   bool
	sF, sN, sX, sA bool
	timing       int
	skipDisc     bool
	discOnly     bool
	versionDet   bool
	osDetect     bool
	dns          bool
	rate         int
	randomize    bool
	verbose      bool
	outNormal    string
	outXML       string
	outGrepable  string
	outJSON      string
	outCSV       string
	sortBy       string
	pingOnly     bool
	banner       bool
	traceroute   bool
	trMax        int
	dirSearch    bool
	subBrute     bool
	whois        bool
	dnsRecords   bool
	webCheck     bool
	useHTTPS     bool
	showHelp     bool
}

func main() {
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
	flag.BoolVar(&f.showHelp, "h", false, "显示帮助")
	flag.Parse()

	if f.showHelp || f.targets == "" {
		flag.Usage()
		os.Exit(1)
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

	opts := buildOptions(f)
	results, err := runScan(opts, f)
	if err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}

	sortResults(results, f.sortBy)
	writeOutputs(f, results)

	if f.banner {
		grabBanners(results)
	}

	printSummary(results)
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
		rtt, ok := scanner.Ping(ip, timeout)
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
	scanner.SubdomainBrute(domain, 50, 3*time.Second, func(sub, ip string) {
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

// ---- 输出文件 ----

func writeOutputs(f cliFlags, results []scanner.Result) {
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
	Protocol string    `xml:"protocol,attr"`
	PortID   int       `xml:"portid,attr"`
	State    xmlState  `xml:"state"`
	Service  xmlSvc    `xml:"service"`
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
