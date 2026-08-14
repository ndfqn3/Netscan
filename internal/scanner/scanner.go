package scanner

import (
	"context"
	"math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sync/semaphore"
)

// Scanner 扫描引擎
type Scanner struct {
	opts       Options
	onResult   func(Result)
	onProgress func(Progress)
	stop       chan struct{}
	stopOnce   sync.Once

	hosts       []string
	ports       []int
	timeout     time.Duration
	concurrency int
	rate        *rateLimiter
	latency     map[string]time.Duration
}

// NewScanner 创建扫描器
func NewScanner(opts Options, onResult func(Result), onProgress func(Progress)) *Scanner {
	return &Scanner{
		opts:       opts,
		onResult:   onResult,
		onProgress: onProgress,
		stop:       make(chan struct{}),
		latency:    make(map[string]time.Duration),
	}
}

// Stop 停止扫描
func (s *Scanner) Stop() {
	s.stopOnce.Do(func() { close(s.stop) })
}

// log 输出日志/提示信息
func (s *Scanner) log(msg string) {
	if s.onProgress != nil {
		s.onProgress(Progress{Message: msg})
	}
}

// timingParams 根据定时模板返回超时与并发数
func timingParams(t int) (time.Duration, int) {
	switch t {
	case 0: // paranoid 偏执
		return 5 * time.Minute, 1
	case 1: // sneaky 隐秘
		return 15 * time.Second, 5
	case 2: // polite 礼貌
		return 1200 * time.Millisecond, 50
	case 3: // normal 常规
		return time.Second, 500
	case 4: // aggressive 激进
		return 500 * time.Millisecond, 2000
	case 5: // insane 疯狂
		return 300 * time.Millisecond, 10000
	default:
		return time.Second, 500
	}
}

// Run 执行扫描
func (s *Scanner) Run() error {
	// 代理设置(结束后清空)
	setProxy(s.opts.ProxyURL)
	defer setProxy("")

	// proot 安全降级
	if applyProotSafety(&s.opts) && s.opts.Verbose {
		s.log("检测到 proot/Termux 环境, 已禁用 raw socket 并降低并发")
	}

	// 解析目标(含数量上限校验, 防止误扫大网段)
	hosts, err := parseTargets(s.opts.Targets, s.opts.MaxTargets)
	if err != nil {
		return err
	}
	s.hosts = hosts

	// 解析端口
	s.ports = parsePortSpec(s.opts.Ports)
	if s.opts.ExcludePorts != "" {
		excluded := parsePortSpec(s.opts.ExcludePorts)
		excludeSet := make(map[int]bool, len(excluded))
		for _, p := range excluded {
			excludeSet[p] = true
		}
		filtered := s.ports[:0]
		for _, p := range s.ports {
			if !excludeSet[p] {
				filtered = append(filtered, p)
			}
		}
		s.ports = filtered
	}
	if s.opts.Randomize {
		rand.Shuffle(len(s.ports), func(i, j int) {
			s.ports[i], s.ports[j] = s.ports[j], s.ports[i]
		})
	}

	// 速率限制
	if s.opts.Rate > 0 {
		s.rate = newRateLimiter(s.opts.Rate)
	}

	// 定时模板
	s.timeout = s.opts.Timeout
	s.concurrency = s.opts.Concurrency
	if s.opts.Timing >= 0 && s.opts.Timing <= 5 {
		if s.opts.Timeout == 0 {
			s.timeout, _ = timingParams(s.opts.Timing)
		}
		if s.opts.Concurrency == 0 {
			_, s.concurrency = timingParams(s.opts.Timing)
		}
	}
	if s.timeout == 0 {
		s.timeout = time.Second
	}
	if s.concurrency <= 0 {
		s.concurrency = 500
	}

	// 初始化 raw scanner(SYN/FIN 等)
	raw := s.initRawScanner()
	if raw != nil {
		defer raw.close()
	}

	totalHosts := len(hosts)
	var scannedHosts int64

	// 主机发现
	upHosts := s.discoverHosts(hosts)

	// 仅主机发现模式: 只列出存活/离线主机, 不做端口扫描
	if s.opts.DiscoveryOnly {
		if s.opts.SkipDiscovery {
			for _, ip := range upHosts {
				s.emitHostUp(ip, 0)
			}
		}
		s.report(Progress{TotalHosts: totalHosts, ScannedHost: len(upHosts), Message: "主机发现完成"})
		return nil
	}

	// 计算总探测数用于进度
	scanCount := len(s.optScanTypes())
	totalProbes := int64(len(upHosts) * len(s.ports) * scanCount)
	var doneProbes int64

	s.report(Progress{TotalHosts: totalHosts, ScannedHost: 0, TotalPorts: len(s.ports), ScannedPort: 0, Message: "开始扫描..."})

	// 并发控制
	sem := semaphore.NewWeighted(int64(s.concurrency))
	ctx := context.Background()

	var wg sync.WaitGroup
	for _, ip := range upHosts {
		ip := ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-s.stop:
				return
			default:
			}
			host := s.scanHost(ip, raw, sem, ctx, &doneProbes, totalProbes, &scannedHosts, totalHosts)
			_ = host
		}()
	}
	wg.Wait()

	s.report(Progress{TotalHosts: totalHosts, ScannedHost: int(atomic.LoadInt64(&scannedHosts)), TotalPorts: len(s.ports), ScannedPort: int(atomic.LoadInt64(&doneProbes)), Percent: 100, Message: "扫描完成"})
	return nil
}

func (s *Scanner) optScanTypes() []ScanType {
	if len(s.opts.ScanTypes) == 0 {
		return []ScanType{ScanTCPConnect}
	}
	return s.opts.ScanTypes
}

// initRawScanner 尝试初始化 raw socket 扫描器
func (s *Scanner) initRawScanner() *rawScanner {
	needRaw := false
	for _, st := range s.optScanTypes() {
		switch st {
		case ScanTCPSYN, ScanFIN, ScanNULL, ScanXMAS, ScanACK:
			needRaw = true
		}
	}
	if !needRaw {
		return nil
	}
	raw, err := newRawScanner()
	if err != nil {
		return nil
	}
	return raw
}

// discoverHosts 主机发现
func (s *Scanner) discoverHosts(hosts []string) []string {
	if s.opts.SkipDiscovery {
		return hosts
	}

	total := len(hosts)
	var up []string
	var wg sync.WaitGroup
	var mu sync.Mutex
	var done int64

	sem := semaphore.NewWeighted(int64(s.concurrency))
	for _, ip := range hosts {
		ip := ip
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sem.Acquire(context.Background(), 1)
			defer sem.Release(1)

			select {
			case <-s.stop:
				return
			default:
			}
			if upNow, latency := isHostUp(ip, s.timeout); upNow {
				mu.Lock()
				up = append(up, ip)
				s.latency[ip] = latency
				mu.Unlock()
				s.emitHostUp(ip, latency)
				if s.opts.StopAfterHost {
					s.log("命中首个存活主机 " + ip + ", 停止扫描")
					s.Stop()
				}
			} else if s.opts.DiscoveryOnly {
				s.emitHostDown(ip)
			}
			atomic.AddInt64(&done, 1)
			s.report(Progress{
				TotalHosts:  total,
				ScannedHost: int(atomic.LoadInt64(&done)),
				Message:     "发现主机 " + ip,
			})
		}()
	}
	wg.Wait()

	// 未找到存活主机时, 端口扫描模式回退为扫描全部; 仅主机发现模式则保留空结果
	if len(up) == 0 && !s.opts.DiscoveryOnly {
		return hosts
	}
	return up
}

// emitHostUp 主机存活结果
func (s *Scanner) emitHostUp(ip string, latency time.Duration) {
	if s.onResult != nil {
		s.onResult(Result{IP: ip, State: "up", Latency: latency})
	}
}

// emitHostDown 主机离线结果
func (s *Scanner) emitHostDown(ip string) {
	if s.onResult != nil {
		s.onResult(Result{IP: ip, State: "down"})
	}
}

// scanHost 扫描单个主机, 结果实时输出
func (s *Scanner) scanHost(ip string, raw *rawScanner, sem *semaphore.Weighted, ctx context.Context, doneProbes *int64, totalProbes int64, scannedHosts *int64, totalHosts int) Host {
	host := Host{IP: ip, Latency: s.latency[ip]}

	// 反向 DNS
	if s.opts.ResolveDNS {
		host.Hostname = reverseLookup(ip)
	}

	// UDP 扫描器
	var udp *udpScanner
	needUDP := false
	for _, st := range s.optScanTypes() {
		if st == ScanUDP {
			needUDP = true
		}
	}
	if needUDP {
		udp, _ = newUDPScanner(ip)
		if udp != nil {
			defer udp.close()
		}
	}

	var wg sync.WaitGroup
	var portMu sync.Mutex
	var openPorts []Port
	for _, port := range s.ports {
		port := port
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case <-s.stop:
				return
			default:
			}
			_ = sem.Acquire(ctx, 1)
			defer sem.Release(1)

			// 逐扫描技术探测, 按协议聚合状态
			states := make(map[string]PortState)
			for _, st := range s.optScanTypes() {
				select {
				case <-s.stop:
					return
				default:
				}
				state := s.probePort(ip, port, st, raw, udp)
				protocol := "tcp"
				if st == ScanUDP {
					protocol = "udp"
				}
				if prev, ok := states[protocol]; ok {
					states[protocol] = betterState(prev, state)
				} else {
					states[protocol] = state
				}
				atomic.AddInt64(doneProbes, 1)
			}

			// 实时输出该端口的探测结果
			for protocol, state := range states {
				s.emitPort(ip, host.Hostname, port, protocol, state, host.Latency)
				if state == StateOpen || state == StateOpenFiltered {
					portMu.Lock()
					openPorts = append(openPorts, Port{Number: port, Protocol: protocol, State: state})
					portMu.Unlock()
				}
			}
		}()
	}
	wg.Wait()

	// 操作系统识别(基于 TTL + 开放端口特征)
	if s.opts.OSDetect {
		if info := detectOS(ip, openPorts, s.timeout); info != nil && info.Family != "" && info.Family != "未知" {
			host.OS = info
			s.emitOS(ip, host.Hostname, info)
		}
	}

	atomic.AddInt64(scannedHosts, 1)
	s.report(Progress{
		TotalHosts:  totalHosts,
		ScannedHost: int(atomic.LoadInt64(scannedHosts)),
		TotalPorts:  len(s.ports),
		ScannedPort: int(atomic.LoadInt64(doneProbes)),
		Message:     "扫描主机 " + ip,
	})
	return host
}

// isHTTPService 判断服务是否为 HTTP 类(用于 CMS 指纹识别触发)
func isHTTPService(s string) bool {
	switch s {
	case "http", "https", "http-alt", "http-proxy", "https-alt", "unknown":
		return true
	}
	return false
}

// emitPort 实时输出单个端口的扫描结果(含服务识别)
func (s *Scanner) emitPort(ip, hostname string, port int, protocol string, state PortState, latency time.Duration) {
	if state != StateOpen && state != StateOpenFiltered && state != StateUnfiltered {
		if !s.opts.Verbose {
			return
		}
	}

	service := lookupService(port, protocol)
	version := ""
	if protocol == "tcp" && state == StateOpen && (s.opts.ServiceDetect || s.opts.VersionDetect) {
		service, version = detectService(ip, port, protocol, s.timeout)
	}

	// POC 高危未授权检测与 CMS 指纹识别
	vuln := ""
	if state == StateOpen {
		if s.opts.POC {
			vuln = RunPOC(ip, port, s.timeout)
		}
		if s.opts.Fingerprint && protocol == "tcp" && isHTTPService(service) {
			if fp := Fingerprint(ip, port, false, 2*time.Second); fp != "" {
				service = fp
				version = ""
			}
		}
	}

	if s.onResult != nil {
		s.onResult(Result{
			IP:       ip,
			Hostname: hostname,
			Port:     port,
			Protocol: protocol,
			State:    state,
			Service:  service,
			Version:  version,
			Vuln:     vuln,
			Latency:  latency,
		})
	}

	// 命中开放端口后立即停止
	if s.opts.StopAfterHost && state == StateOpen {
		s.Stop()
	}
}

// emitOS 输出操作系统识别结果
func (s *Scanner) emitOS(ip, hostname string, info *OSInfo) {
	if s.onResult == nil || info == nil {
		return
	}
	s.onResult(Result{
		IP:       ip,
		Hostname: hostname,
		State:    "os",
		Service:  "操作系统",
		Version:  info.Name,
		OS:       info.Family,
	})
}

// probePort 对单个端口执行单个扫描技术
func (s *Scanner) probePort(ip string, port int, st ScanType, raw *rawScanner, udp *udpScanner) PortState {
	if s.rate != nil {
		s.rate.wait()
	}
	switch st {
	case ScanTCPConnect:
		return tcpConnectScan(ip, port, s.timeout)
	case ScanTCPSYN:
		if raw != nil {
			return raw.probe(ip, port, flagSYN, s.timeout)
		}
		return tcpConnectScan(ip, port, s.timeout)
	case ScanFIN:
		if raw != nil {
			return raw.probe(ip, port, flagFIN, s.timeout)
		}
		return StateFiltered
	case ScanNULL:
		if raw != nil {
			return raw.probe(ip, port, 0, s.timeout)
		}
		return StateFiltered
	case ScanXMAS:
		if raw != nil {
			return raw.probe(ip, port, flagFIN|flagURG|flagPSH, s.timeout)
		}
		return StateFiltered
	case ScanACK:
		if raw != nil {
			return raw.probe(ip, port, flagACK, s.timeout)
		}
		return StateFiltered
	case ScanUDP:
		if udp != nil {
			return udp.probe(port, s.timeout)
		}
		return StateOpenFiltered
	}
	return StateFiltered
}

// betterState 状态优先级: open > unfiltered > open|filtered > closed > filtered
func betterState(a, b PortState) PortState {
	rank := func(s PortState) int {
		switch s {
		case StateOpen:
			return 5
		case StateUnfiltered:
			return 4
		case StateOpenFiltered:
			return 3
		case StateClosed:
			return 2
		case StateFiltered:
			return 1
		}
		return 0
	}
	if rank(b) > rank(a) {
		return b
	}
	return a
}

func (s *Scanner) report(p Progress) {
	if p.TotalPorts > 0 && p.TotalHosts > 0 {
		total := float64(p.TotalHosts * p.TotalPorts)
		if total > 0 {
			p.Percent = float64(p.ScannedPort) / total * 100
		}
	}
	if s.onProgress != nil {
		s.onProgress(p)
	}
}

// reverseLookup 反向 DNS 解析(纯 Go 解析器 + 超时, 避免 cgo 解析器阻塞导致界面卡死)
func reverseLookup(ip string) string {
	r := &net.Resolver{PreferGo: true}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	names, err := r.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return names[0]
}
