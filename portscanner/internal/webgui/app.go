package webgui

import (
	_ "embed"
	"encoding/json"
	"fmt"
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
	ScanTypes     []string `json:"scan_types"`
	Timing        int      `json:"timing"`
	SkipDiscovery bool     `json:"skip_discovery"`
	DiscoveryOnly bool     `json:"discovery_only"`
	ServiceDetect bool     `json:"service_detect"`
	VersionDetect bool     `json:"version_detect"`
	OSDetect      bool     `json:"os_detect"`
	ResolveDNS    bool     `json:"resolve_dns"`
	DirSearch     bool     `json:"dir_search"`
	WebCheck      bool     `json:"web_check"`
	SubBrute      bool     `json:"sub_brute"`
	Whois         bool     `json:"whois"`
	DNSRecords    bool     `json:"dns_records"`
	UseHTTPS      bool     `json:"use_https"`
}

// Run 启动基于 WebView 的图形界面
func Run() {
	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("NetScan 网络扫描器")
	w.SetSize(1280, 860, webview.HintNone)

	var mu sync.Mutex
	var current *scanner.Scanner

	// UI 更新器: 收集 JS 片段, 由单一 goroutine 批量刷入,
	// 避免多 goroutine 并发调用 Dispatch/Eval 触发 webview 崩溃
	var uiMu sync.Mutex
	var pending []string
	dispatchJS := func(js string) {
		uiMu.Lock()
		pending = append(pending, js)
		uiMu.Unlock()
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

		s := scanner.NewScanner(opts,
			func(r scanner.Result) {
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
		}()

		// Web 侦察
		if req.DirSearch || req.WebCheck || req.SubBrute || req.Whois || req.DNSRecords {
			go runRecon(req, func(line string) {
				dispatchJS("window.addRecon(" + strconv.Quote(line) + ")")
			})
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

	w.SetHtml(indexHTML)
	w.Run()
}

func buildOptions(req scanRequest) scanner.Options {
	opts := scanner.DefaultOptions()
	opts.Targets = req.Targets
	opts.Ports = req.Ports
	opts.Timing = req.Timing
	opts.Timeout = 0
	opts.Concurrency = 0
	opts.SkipDiscovery = req.SkipDiscovery
	opts.DiscoveryOnly = req.DiscoveryOnly
	opts.ServiceDetect = req.ServiceDetect
	opts.VersionDetect = req.VersionDetect
	opts.OSDetect = req.OSDetect
	opts.ResolveDNS = req.ResolveDNS

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
		push(fmt.Sprintf("========== 子域名爆破 %s ==========", domain))
		scanner.SubdomainBrute(domain, 50, timeout, func(sub, ip string) {
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
