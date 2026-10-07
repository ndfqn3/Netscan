// Package ffufrun 把 ffuf(MIT, Copyright (c) 2021 Joona Hoikkala)以库的形式集成到 NetScan:
// 复用其完整引擎(字典/多关键字/Encoder/匹配过滤/自动校准/递归/Scraper/预检请求等),
// 输出通过回调逐行返回(供 CLI/GUI 使用), 并扩展子域名/虚拟主机爆破模式。
// 源码见 third_party/ffuf。
package ffufrun

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/assembly"
	"github.com/ffuf/ffuf/v2/pkg/engine"
	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/filter"
	"github.com/ffuf/ffuf/v2/pkg/output"

	"portscanner/internal/payloads"
)

// Config ffuf 扫描配置(JSON 友好; 字段与 ffuf CLI 选项一一对应)
type Config struct {
	// ---- 便捷模式(NetScan 扩展) ----
	Mode      string `json:"mode"`      // ""/url | subdomain/子域名 | vhost/虚拟主机
	Subdomain string `json:"subdomain"` // 子域名爆破的根域名(生成 http://FUZZ.<domain>)
	VHost     string `json:"vhost"`     // 虚拟主机爆破的域名(注入 Host: FUZZ.<domain>)
	Scheme    string `json:"scheme"`    // http(默认)/https
	Port      int    `json:"port"`      // 可选端口(0=默认)

	// ---- 输入(InputOptions) ----
	Wordlists              []string `json:"wordlists"`  // 可含 file:KEYWORD
	Wordlist               string   `json:"wordlist"`   // 兼容旧字段(单个词表)
	InputMode              string   `json:"input_mode"` // clusterbomb/pitchfork/sniper
	InputNum               int      `json:"input_num"`
	InputShell             string   `json:"input_shell"`
	InputCommands          []string `json:"input_commands"`
	Request                string   `json:"request_file"`
	RequestProto           string   `json:"request_proto"`
	Extensions             string   `json:"extensions"`
	IgnoreWordlistComments bool     `json:"ignore_wordlist_comments"`
	DirSearchCompat        bool     `json:"dirsearch_compat"`
	Encoders               []string `json:"encoders"`

	// ---- 常规(GeneralOptions) ----
	Threads                   int      `json:"threads"`
	Rate                      int      `json:"rate"`
	Delay                     string   `json:"delay"`
	MaxTime                   int      `json:"maxtime"`
	MaxTimeJob                int      `json:"maxtime_job"`
	StopOn403                 bool     `json:"stop_on_403"`
	StopOnAll                 bool     `json:"stop_on_all"`
	StopOnErrors              bool     `json:"stop_on_errors"`
	AutoCalibration           bool     `json:"autocalibration"`
	AutoCalibrationKeyword    string   `json:"autocalibration_keyword"`
	AutoCalibrationPerHost    bool     `json:"autocalibration_per_host"`
	AutoCalibrationStrategies []string `json:"autocalibration_strategies"`
	AutoCalibrationStrings    []string `json:"autocalibration_strings"`
	Quiet                     bool     `json:"quiet"`
	Verbose                   bool     `json:"verbose"`
	JSON                      bool     `json:"json"`

	// ---- HTTP(HTTPOptions) ----
	URL               string   `json:"url"`
	Method            string   `json:"method"`
	Data              string   `json:"data"`
	Headers           []string `json:"headers"`
	Cookies           []string `json:"cookies"`
	Follow            bool     `json:"follow"`           // 兼容旧字段
	FollowRedirects   bool     `json:"follow_redirects"` // 兼容旧字段
	IgnoreBody        bool     `json:"ignore_body"`
	Proxy             string   `json:"proxy"`     // 兼容旧字段
	ProxyURL          string   `json:"proxy_url"` // 兼容旧字段
	ReplayProxyURL    string   `json:"replay_proxy_url"`
	RawHTTP           bool     `json:"raw"`
	Recursion         bool     `json:"recursion"`
	RecursionDepth    int      `json:"recursion_depth"`
	RecursionStrategy string   `json:"recursion_strategy"`
	Timeout           int      `json:"timeout"`
	SNI               string   `json:"sni"`
	HTTP2             bool     `json:"http2"`
	ClientCert        string   `json:"client-cert"`
	ClientKey         string   `json:"client-key"`

	// ---- 匹配(MatcherOptions) ----
	MatcherMode string `json:"matcher_mode"`
	MC          string `json:"mc"`
	MS          string `json:"ms"`
	MW          string `json:"mw"`
	ML          string `json:"ml"`
	MR          string `json:"mr"`
	MT          string `json:"mt"`

	// ---- 过滤(FilterOptions) ----
	FilterMode string `json:"filter_mode"`
	FC         string `json:"fc"`
	FS         string `json:"fs"`
	FW         string `json:"fw"`
	FL         string `json:"fl"`
	FR         string `json:"fr"`
	FT         string `json:"ft"`

	// ---- 输出(OutputOptions) ----
	OutputDirectory     string `json:"output_directory"`
	OutputFile          string `json:"output_file"`
	OutputFormat        string `json:"output_format"`
	OutputSkipEmptyFile bool   `json:"output_skip_empty"`
	AuditLog            string `json:"audit_log"`
	DebugLog            string `json:"debug_log"`
	Scrapers            string `json:"scrapers"`
	ScraperFile         string `json:"scraperfile"`
}

// Runner 运行中的 fuzz 任务
type Runner struct {
	job  *engine.Job
	done chan struct{}
	mu   sync.Mutex
}

// BuildURL 根据模式生成 ffuf 目标 URL(供 CLI/GUI 预览与校验)
func BuildURL(cfg *Config) string {
	if cfg.URL != "" && cfg.Mode != "subdomain" && cfg.Mode != "sub" && cfg.Mode != "子域名" {
		return cfg.URL
	}
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = "http"
	}
	host := cfg.Subdomain
	if host == "" {
		return cfg.URL
	}
	port := ""
	if cfg.Port > 0 {
		port = fmt.Sprintf(":%d", cfg.Port)
	}
	return fmt.Sprintf("%s://FUZZ.%s%s", scheme, host, port)
}

// Run 启动 fuzz 任务(onLine 逐行回调), 返回 Runner 供 Wait/Stop
func Run(cfg Config, onLine func(string)) (*Runner, error) {
	opts := ffuf.NewConfigOptions()

	// 模式解析: 子域名爆破 / 虚拟主机爆破
	mode := strings.ToLower(cfg.Mode)
	switch mode {
	case "subdomain", "sub", "子域名":
		cfg.URL = BuildURL(&cfg)
		cfg.AutoCalibration = true // 通配符 DNS/泛解析需要自动校准
	case "vhost", "虚拟主机":
		if cfg.VHost == "" {
			return nil, fmt.Errorf("vhost 模式需要指定域名")
		}
		if cfg.URL == "" {
			return nil, fmt.Errorf("vhost 模式需要指定目标 URL(如 http://IP:PORT/)")
		}
		cfg.Headers = append(cfg.Headers, "Host: FUZZ."+cfg.VHost)
		cfg.AutoCalibration = true
	}
	if cfg.URL == "" && cfg.Request == "" {
		return nil, fmt.Errorf("必须指定 --fuzz-url(或子域名/虚拟主机模式参数/--fuzz-request)")
	}

	// 词表: 兼容单字段 + 多词表; builtin:<name> 解析为内置 payload 字典
	if cfg.Wordlist != "" {
		cfg.Wordlists = append(cfg.Wordlists, cfg.Wordlist)
	}
	for _, w := range cfg.Wordlists {
		if w == "" {
			continue
		}
		if strings.HasPrefix(w, "builtin:") {
			p, err := payloads.Materialize(strings.TrimPrefix(w, "builtin:"))
			if err != nil {
				return nil, err
			}
			w = p
		}
		opts.Input.Wordlists = append(opts.Input.Wordlists, w)
	}

	opts.HTTP.URL = cfg.URL
	if cfg.Method != "" {
		opts.HTTP.Method = cfg.Method
	}
	opts.HTTP.Data = cfg.Data
	if len(cfg.Headers) > 0 {
		opts.HTTP.Headers = cfg.Headers
	}
	if len(cfg.Cookies) > 0 {
		opts.HTTP.Cookies = cfg.Cookies
	}
	opts.Input.Extensions = cfg.Extensions
	if cfg.InputMode != "" {
		opts.Input.InputMode = cfg.InputMode
	}
	if cfg.InputNum > 0 {
		opts.Input.InputNum = cfg.InputNum
	}
	opts.Input.InputShell = cfg.InputShell
	opts.Input.Inputcommands = cfg.InputCommands
	opts.Input.Request = cfg.Request
	if cfg.RequestProto != "" {
		opts.Input.RequestProto = cfg.RequestProto
	}
	opts.Input.IgnoreWordlistComments = cfg.IgnoreWordlistComments
	opts.Input.DirSearchCompat = cfg.DirSearchCompat
	opts.Input.Encoders = cfg.Encoders

	if cfg.Threads > 0 {
		opts.General.Threads = cfg.Threads
	}
	opts.General.Rate = cfg.Rate
	opts.General.Delay = cfg.Delay
	opts.General.MaxTime = cfg.MaxTime
	opts.General.MaxTimeJob = cfg.MaxTimeJob
	opts.General.StopOn403 = cfg.StopOn403
	opts.General.StopOnAll = cfg.StopOnAll
	opts.General.StopOnErrors = cfg.StopOnErrors
	opts.General.AutoCalibration = cfg.AutoCalibration
	if cfg.AutoCalibrationKeyword != "" {
		opts.General.AutoCalibrationKeyword = cfg.AutoCalibrationKeyword
	}
	opts.General.AutoCalibrationPerHost = cfg.AutoCalibrationPerHost
	if len(cfg.AutoCalibrationStrategies) > 0 {
		opts.General.AutoCalibrationStrategies = cfg.AutoCalibrationStrategies
	}
	opts.General.AutoCalibrationStrings = cfg.AutoCalibrationStrings
	opts.General.Quiet = cfg.Quiet
	opts.General.Verbose = cfg.Verbose
	opts.General.Json = cfg.JSON

	if cfg.Timeout > 0 {
		opts.HTTP.Timeout = cfg.Timeout
	}
	opts.HTTP.FollowRedirects = cfg.Follow || cfg.FollowRedirects
	opts.HTTP.IgnoreBody = cfg.IgnoreBody
	opts.HTTP.ProxyURL = cfg.ProxyURL
	if opts.HTTP.ProxyURL == "" {
		opts.HTTP.ProxyURL = cfg.Proxy
	}
	opts.HTTP.ReplayProxyURL = cfg.ReplayProxyURL
	opts.HTTP.Raw = cfg.RawHTTP
	opts.HTTP.Recursion = cfg.Recursion
	if cfg.RecursionDepth > 0 {
		opts.HTTP.RecursionDepth = cfg.RecursionDepth
	}
	if cfg.RecursionStrategy != "" {
		opts.HTTP.RecursionStrategy = cfg.RecursionStrategy
	}
	opts.HTTP.SNI = cfg.SNI
	opts.HTTP.Http2 = cfg.HTTP2
	opts.HTTP.ClientCert = cfg.ClientCert
	opts.HTTP.ClientKey = cfg.ClientKey

	if cfg.MatcherMode != "" {
		opts.Matcher.Mode = cfg.MatcherMode
	}
	if cfg.MC != "" {
		opts.Matcher.Status = cfg.MC
	}
	if cfg.MS != "" {
		opts.Matcher.Size = cfg.MS
	}
	if cfg.MW != "" {
		opts.Matcher.Words = cfg.MW
	}
	if cfg.ML != "" {
		opts.Matcher.Lines = cfg.ML
	}
	if cfg.MR != "" {
		opts.Matcher.Regexp = cfg.MR
	}
	if cfg.MT != "" {
		opts.Matcher.Time = cfg.MT
	}

	if cfg.FilterMode != "" {
		opts.Filter.Mode = cfg.FilterMode
	}
	if cfg.FC != "" {
		opts.Filter.Status = cfg.FC
	}
	if cfg.FS != "" {
		opts.Filter.Size = cfg.FS
	}
	if cfg.FW != "" {
		opts.Filter.Words = cfg.FW
	}
	if cfg.FL != "" {
		opts.Filter.Lines = cfg.FL
	}
	if cfg.FR != "" {
		opts.Filter.Regexp = cfg.FR
	}
	if cfg.FT != "" {
		opts.Filter.Time = cfg.FT
	}

	opts.Output.OutputDirectory = cfg.OutputDirectory
	opts.Output.OutputFile = cfg.OutputFile
	if cfg.OutputFormat != "" {
		opts.Output.OutputFormat = cfg.OutputFormat
	}
	opts.Output.OutputSkipEmptyFile = cfg.OutputSkipEmptyFile
	opts.Output.AuditLog = cfg.AuditLog
	opts.Output.DebugLog = cfg.DebugLog
	if cfg.Scrapers != "" {
		opts.General.Scrapers = cfg.Scrapers
	}
	opts.General.ScraperFile = cfg.ScraperFile

	opts.General.Noninteractive = true
	opts.General.Colors = false

	ctx, cancel := context.WithCancel(context.Background())
	// 初始化 ffuf 配置目录(scraper/auto-calibration), 与 ffuf CLI 行为一致
	if err := ffuf.CheckOrCreateConfigDir(); err != nil {
		cancel()
		return nil, fmt.Errorf("初始化 ffuf 配置目录失败: %w", err)
	}
	conf, err := ffuf.ConfigFromOptions(opts, ctx, cancel)
	if err != nil {
		cancel()
		return nil, err
	}
	conf.Noninteractive = true

	job, err := assembly.BuildJob(conf)
	if err != nil {
		cancel()
		return nil, err
	}

	// 默认状态匹配器: 未显式给出其他匹配器时安装(与 ffuf CLI 行为一致)
	statusSet := cfg.MC != ""
	matcherSet := cfg.MS != "" || cfg.MW != "" || cfg.ML != "" || cfg.MR != "" || cfg.MT != ""
	mm, err := filter.FromConfig(opts, statusSet || !matcherSet)
	if err != nil {
		cancel()
		return nil, err
	}
	conf.MatcherManager = mm

	if onLine != nil {
		job.Output = &cbOutput{Stdoutput: output.NewStdoutput(conf), onLine: onLine}
	}

	r := &Runner{job: job, done: make(chan struct{})}
	go func() {
		defer close(r.done)
		job.Start()
	}()
	return r, nil
}

// Wait 等待任务结束
func (r *Runner) Wait() {
	if r == nil {
		return
	}
	<-r.done
}

// Stop 停止任务
func (r *Runner) Stop() {
	if r == nil {
		return
	}
	r.mu.Lock()
	j := r.job
	r.mu.Unlock()
	if j != nil {
		j.Stop()
	}
}

// cbOutput 把 ffuf 输出重定向到回调(避免写入 stdout, 供 GUI 使用),
// 同时累积 Result 以便 Finalize 写出 -o 结果文件。
type cbOutput struct {
	*output.Stdoutput
	onLine func(string)
	mu     sync.Mutex
}

func (c *cbOutput) Banner()                {}
func (c *cbOutput) Progress(ffuf.Progress) {}
func (c *cbOutput) Info(s string)          { c.onLine("[*] " + s) }
func (c *cbOutput) Error(s string)         { c.onLine("[-] " + s) }
func (c *cbOutput) Warning(s string)       { c.onLine("[!] " + s) }
func (c *cbOutput) Raw(s string)           { c.onLine(s) }

func (c *cbOutput) Result(resp ffuf.Response) {
	inputs := make(map[string][]byte, len(resp.Request.Input))
	for k, v := range resp.Request.Input {
		inputs[k] = v
	}
	res := ffuf.Result{
		Input:            inputs,
		Position:         resp.Request.Position,
		StatusCode:       resp.StatusCode,
		ContentLength:    resp.ContentLength,
		ContentWords:     resp.ContentWords,
		ContentLines:     resp.ContentLines,
		ContentType:      resp.ContentType,
		RedirectLocation: resp.GetRedirectLocation(false),
		ScraperData:      resp.ScraperData,
		Url:              resp.Request.Url,
		Duration:         resp.Duration,
		ResultFile:       resp.ResultFile,
		Host:             resp.Request.Host,
	}
	c.mu.Lock()
	c.SetCurrentResults(append(c.GetCurrentResults(), res))
	c.mu.Unlock()

	loc := ""
	if res.RedirectLocation != "" {
		loc = " -> " + res.RedirectLocation
	}
	c.onLine(fmt.Sprintf("[Status: %d, Size: %d, Words: %d, Lines: %d, Duration: %s] %s%s",
		res.StatusCode, res.ContentLength, res.ContentWords, res.ContentLines,
		res.Duration.Round(time.Millisecond), res.Url, loc))
}
