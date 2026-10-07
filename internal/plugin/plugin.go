package plugin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"portscanner/internal/netx"
	"portscanner/internal/poc"
	"portscanner/pkg/portscan"
	"sort"
	"strings"
	"text/template"
	"time"

	"gopkg.in/yaml.v3"
)

// Plugin 声明式插件
type Plugin struct {
	ID          string            `json:"id" yaml:"id"`
	Type        string            `json:"type" yaml:"type"`
	Name        string            `json:"name" yaml:"name"`
	Version     string            `json:"version" yaml:"version"`
	Author      string            `json:"author" yaml:"author"`
	Description string            `json:"description" yaml:"description"`
	Platforms   []string          `json:"platforms" yaml:"platforms"`
	Config      map[string]string `json:"config" yaml:"config"`
	Webhook     string            `json:"webhook,omitempty" yaml:"webhook"`
	Source      string            `json:"source" yaml:"-"`
	Enabled     bool              `json:"enabled" yaml:"-"`
	Downloads   int               `json:"downloads,omitempty" yaml:"-"`

	// poc / exploit 插件字段(复用 POC 模板引擎)
	Service  string           `json:"service,omitempty" yaml:"service"`
	Severity string           `json:"severity,omitempty" yaml:"severity"`
	Request  *poc.POCRequest  `json:"request,omitempty" yaml:"request"`
	Response *poc.POCResponse `json:"response,omitempty" yaml:"response"`

	// report / output 插件字段(Go template 渲染)
	Format   string `json:"format,omitempty" yaml:"format"`
	Template string `json:"template,omitempty" yaml:"template"`
}

// PluginManager 插件管理
type PluginManager struct {
	dir string
}

func DefaultPluginDir() string {
	return netx.ResolveDataDir("plugins", ".netscan_plugins")
}

func OpenPluginManager(dir string) *PluginManager {
	if dir == "" {
		dir = DefaultPluginDir()
	}
	_ = os.MkdirAll(dir, 0o755)
	return &PluginManager{dir: dir}
}

func (m *PluginManager) statePath() string {
	return filepath.Join(m.dir, ".state.json")
}

func (m *PluginManager) loadState() map[string]bool {
	state := map[string]bool{}
	if data, err := os.ReadFile(m.statePath()); err == nil {
		_ = json.Unmarshal(data, &state)
	}
	return state
}

func (m *PluginManager) saveState(state map[string]bool) {
	data, _ := json.MarshalIndent(state, "", "  ")
	_ = os.WriteFile(m.statePath(), data, 0o644)
}

// List 列出所有插件(内置 + 用户)
func (m *PluginManager) List() []Plugin {
	state := m.loadState()
	var out []Plugin
	for _, p := range builtinPlugins() {
		p.Source = "builtin"
		if enabled, ok := state[p.ID]; ok {
			p.Enabled = enabled
		} else {
			p.Enabled = true
		}
		out = append(out, p)
	}
	entries, _ := os.ReadDir(m.dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".json") {
			continue
		}
		p, err := loadPluginFile(filepath.Join(m.dir, e.Name()))
		if err == nil && p != nil {
			p.Source = "user"
			if enabled, ok := state[p.ID]; ok {
				p.Enabled = enabled
			} else {
				p.Enabled = true
			}
			out = append(out, *p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Enable 启用插件
func (m *PluginManager) Enable(id string) error {
	state := m.loadState()
	state[id] = true
	m.saveState(state)
	return nil
}

// Disable 禁用插件
func (m *PluginManager) Disable(id string) error {
	state := m.loadState()
	state[id] = false
	m.saveState(state)
	return nil
}

// Install 从本地文件安装
func (m *PluginManager) Install(path string) error {
	p, err := loadPluginFile(path)
	if err != nil {
		return err
	}
	data, _ := os.ReadFile(path)
	return os.WriteFile(filepath.Join(m.dir, netx.SanitizeID(p.ID)+filepath.Ext(path)), data, 0o644)
}

// Remove 卸载插件(内置插件仅禁用不删除)
func (m *PluginManager) Remove(id string) error {
	for _, p := range builtinPlugins() {
		if p.ID == id {
			return fmt.Errorf("内置插件不可卸载, 可禁用")
		}
	}
	entries, _ := os.ReadDir(m.dir)
	for _, e := range entries {
		pp, err := loadPluginFile(filepath.Join(m.dir, e.Name()))
		if err == nil && pp.ID == id {
			return os.Remove(filepath.Join(m.dir, e.Name()))
		}
	}
	return fmt.Errorf("未找到插件: %s", id)
}

// POCs 返回启用状态下的 poc/exploit 插件对应的 POC 模板(供 ScanPOCs 使用)
func (m *PluginManager) POCs() []poc.POCTemplate {
	var out []poc.POCTemplate
	for _, p := range m.List() {
		if !p.Enabled || (p.Type != "poc" && p.Type != "exploit") {
			continue
		}
		if p.Request == nil {
			continue
		}
		t := poc.POCTemplate{
			ID:       p.ID,
			Name:     p.Name,
			Service:  p.Service,
			Severity: p.Severity,
			Request:  *p.Request,
		}
		if p.Response != nil {
			t.Response = *p.Response
		}
		out = append(out, t)
	}
	return out
}

// Notify 将扫描结果推送到启用状态的 notification 插件 webhook
func (m *PluginManager) Notify(results []portscan.Result) {
	for _, p := range m.List() {
		if !p.Enabled || p.Type != "notification" || p.Webhook == "" {
			continue
		}
		payload, _ := json.Marshal(map[string]interface{}{
			"plugin":  p.Name,
			"results": results,
		})
		client := &http.Client{Timeout: 5 * time.Second}
		req, _ := http.NewRequest("POST", p.Webhook, strings.NewReader(string(payload)))
		req.Header.Set("Content-Type", "application/json")
		if resp, err := client.Do(req); err == nil {
			_ = resp.Body.Close()
		}
	}
}

// ReportData 报告模板渲染数据
type ReportData struct {
	Target    string
	Ports     string
	HostCount int
	OpenCount int
	VulnCount int
	Results   []portscan.Result
}

// GenerateReports 用启用状态的 report 插件模板生成报告文件, 返回生成的文件路径
func (m *PluginManager) GenerateReports(target, ports string, results []portscan.Result) []string {
	data := ReportData{Target: target, Ports: ports, Results: results}
	for _, r := range results {
		switch r.State {
		case "up":
			data.HostCount++
		case portscan.StateOpen, portscan.StateOpenFiltered:
			data.OpenCount++
			if r.Vuln != "" {
				data.VulnCount++
			}
		}
	}

	var out []string
	for _, p := range m.List() {
		if !p.Enabled || p.Type != "report" || p.Template == "" {
			continue
		}
		tmpl, err := template.New(p.ID).Parse(p.Template)
		if err != nil {
			continue
		}
		var sb strings.Builder
		if err := tmpl.Execute(&sb, data); err != nil {
			continue
		}
		dir := filepath.Join(m.dir, "reports")
		_ = os.MkdirAll(dir, 0o755)
		path := filepath.Join(dir, netx.SanitizeID(p.ID)+"_"+time.Now().Format("20060102_150405")+".txt")
		if os.WriteFile(path, []byte(sb.String()), 0o644) == nil {
			out = append(out, path)
		}
	}
	return out
}

// OutputFormats 返回启用状态的 output 插件的输出格式名
func (m *PluginManager) OutputFormats() []string {
	var out []string
	for _, p := range m.List() {
		if p.Enabled && p.Type == "output" && p.Format != "" {
			out = append(out, p.Format)
		}
	}
	return out
}

// RenderOutput 用启用状态的 output 插件模板逐行渲染开放端口结果, 返回插件名 → 渲染文本
func (m *PluginManager) RenderOutput(results []portscan.Result) map[string]string {
	out := map[string]string{}
	for _, p := range m.List() {
		if !p.Enabled || p.Type != "output" || p.Template == "" {
			continue
		}
		tmpl, err := template.New(p.ID).Parse(p.Template)
		if err != nil {
			continue
		}
		var sb strings.Builder
		for _, r := range results {
			if r.State != portscan.StateOpen && r.State != portscan.StateOpenFiltered {
				continue
			}
			_ = tmpl.Execute(&sb, r)
			sb.WriteString("\n")
		}
		out[p.Name] = sb.String()
	}
	return out
}

// loadPluginFile 从文件加载插件
func loadPluginFile(path string) (*Plugin, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p := &Plugin{}
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		err = json.Unmarshal(data, p)
	} else {
		err = yaml.Unmarshal(data, p)
	}
	if err != nil {
		return nil, err
	}
	if p.ID == "" {
		return nil, fmt.Errorf("插件缺少 id")
	}
	if p.Type == "" {
		p.Type = "poc"
	}
	return p, nil
}

// builtinPlugins 内置示例插件
func builtinPlugins() []Plugin {
	return []Plugin{
		{ID: "builtin-poc", Type: "poc", Name: "内置 POC 引擎", Version: "1.0.0", Author: "NetScan", Description: "200+ 内置漏洞检测规则", Platforms: []string{"all"}},
		{ID: "builtin-report-html", Type: "report", Name: "HTML 报告", Version: "1.0.0", Author: "NetScan", Description: "生成暗色主题 HTML 报告", Platforms: []string{"all"}},
		{ID: "builtin-output-json", Type: "output", Name: "JSON 输出", Version: "1.0.0", Author: "NetScan", Description: "JSON 格式结果输出", Platforms: []string{"all"}},
		{ID: "builtin-notify-webhook", Type: "notification", Name: "Webhook 通知", Version: "1.0.0", Author: "NetScan", Description: "通过 Webhook 推送扫描结果", Platforms: []string{"all"}},
	}
}

// marketURL 插件市场远程地址(空则用内置示例市场)
var marketURL string

// SetMarketURL 设置插件市场远程地址
func SetMarketURL(u string) { marketURL = u }

// MarketplacePlugins 获取插件市场列表(远程优先, 失败回退内置示例)
func MarketplacePlugins() []Plugin {
	if marketURL != "" {
		if list, err := fetchMarket(marketURL + "/plugins"); err == nil && len(list) > 0 {
			return list
		}
	}
	return []Plugin{
		{ID: "redis-unauth", Type: "poc", Name: "Redis 未授权检测", Version: "1.2.0", Author: "NetScan Team", Description: "检测 Redis 未授权访问与写 Shell", Downloads: 1200},
		{ID: "log4shell-detect", Type: "poc", Name: "Log4Shell 检测", Version: "2.0.0", Author: "SecLab", Description: "检测 CVE-2021-44228 Log4j 漏洞", Downloads: 890},
		{ID: "spring4shell", Type: "exploit", Name: "Spring4Shell 利用", Version: "1.0.1", Author: "SecLab", Description: "CVE-2022-22965 检测与利用", Downloads: 650},
		{ID: "tomcat-war-deploy", Type: "exploit", Name: "Tomcat WAR 部署", Version: "1.5.0", Author: "NetScan Team", Description: "Tomcat 管理后台 WAR 部署", Downloads: 430},
		{ID: "pdf-report", Type: "report", Name: "PDF 报告生成", Version: "1.1.0", Author: "ReportLab", Description: "生成 PDF 格式扫描报告", Downloads: 320},
		{ID: "discord-notify", Type: "notification", Name: "Discord 通知", Version: "1.0.0", Author: "NetScan Team", Description: "通过 Discord Webhook 推送结果", Downloads: 210},
	}
}

// fetchMarket 从远程市场拉取插件列表 JSON
func fetchMarket(u string) ([]Plugin, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var list []Plugin
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return nil, err
	}
	return list, nil
}

// InstallMarketPlugin 从市场安装插件(远程市场优先, 失败回退内置生成)
func InstallMarketPlugin(id string) error {
	safeID := netx.SanitizeID(id)
	// 远程市场: 直接下载插件 YAML 文件
	if marketURL != "" {
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Get(marketURL + "/plugins/" + id + ".yaml")
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == 200 {
				data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				if len(data) > 0 {
					m := OpenPluginManager("")
					return os.WriteFile(filepath.Join(m.dir, safeID+".yaml"), data, 0o644)
				}
			}
		}
	}
	for _, p := range MarketplacePlugins() {
		if p.ID == id {
			m := OpenPluginManager("")
			// 用精简结构序列化, 避免内嵌 poc.POCTemplate 的重复 key(id) 导致 panic
			mp := struct {
				ID          string `yaml:"id"`
				Type        string `yaml:"type"`
				Name        string `yaml:"name"`
				Version     string `yaml:"version"`
				Author      string `yaml:"author"`
				Description string `yaml:"description"`
			}{p.ID, p.Type, p.Name, p.Version, p.Author, p.Description}
			data, _ := yaml.Marshal(mp)
			return os.WriteFile(filepath.Join(m.dir, safeID+".yaml"), data, 0o644)
		}
	}
	return fmt.Errorf("市场无此插件: %s", id)
}
