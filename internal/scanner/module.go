package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// FileModule 用户自定义模块(YAML/JSON 文件, 平台化可替换)
type FileModule struct {
	ID       string   `yaml:"id" json:"id"`
	Name     string   `yaml:"name" json:"name"`
	Type     string   `yaml:"type" json:"type"` // detect / exploit
	Severity string   `yaml:"severity" json:"severity"`
	Service  string   `yaml:"service" json:"service"`
	Method   string   `yaml:"method" json:"method"`
	Path     string   `yaml:"path" json:"path"`
	Match    []string `yaml:"match" json:"match"`
	Desc     string   `yaml:"desc" json:"desc"`
}

// ModuleManager 模块管理(平台化: 从 modules/ 目录加载用户模块)
type ModuleManager struct {
	dir string
}

// DefaultModuleDir 默认模块目录
func DefaultModuleDir() string {
	home, _ := os.UserHomeDir()
	if home == "" {
		return "modules"
	}
	return filepath.Join(home, ".netscan_modules")
}

// OpenModuleManager 打开模块管理器
func OpenModuleManager(dir string) *ModuleManager {
	if dir == "" {
		dir = DefaultModuleDir()
	}
	_ = os.MkdirAll(dir, 0o755)
	return &ModuleManager{dir: dir}
}

// List 列出用户模块
func (m *ModuleManager) List() []FileModule {
	var out []FileModule
	entries, _ := os.ReadDir(m.dir)
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".json") {
			continue
		}
		if p, err := loadFileModule(filepath.Join(m.dir, e.Name())); err == nil {
			out = append(out, *p)
		}
	}
	return out
}

// Load 加载用户模块并合并进 vulnModules(跳过已存在的 ID, 防止重复加载)
func (m *ModuleManager) Load() {
	for _, fm := range m.List() {
		if fm.ID == "" || fm.Path == "" {
			continue
		}
		if moduleExists(fm.ID) {
			continue
		}
		method := fm.Method
		if method == "" {
			method = "GET"
		}
		sev := fm.Severity
		if sev == "" {
			sev = "medium"
		}
		desc := fm.Desc
		if desc == "" {
			desc = fm.Name
		}
		vulnModules = append(vulnModules, ExploitModule{
			ID:       fm.ID,
			Service:  "http",
			Severity: sev,
			Desc:     desc,
			Path:     fm.Path,
			Method:   method,
			Match:    fm.Match,
			Type:     fm.Type,
		})
	}
}

// moduleExists 判断模块 ID 是否已存在于 vulnModules(内置或已加载)
func moduleExists(id string) bool {
	for _, m := range vulnModules {
		if m.ID == id {
			return true
		}
	}
	return false
}

// Add 安装模块文件
func (m *ModuleManager) Add(path string) error {
	p, err := loadFileModule(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	ext := filepath.Ext(path)
	return os.WriteFile(filepath.Join(m.dir, p.ID+ext), data, 0o644)
}

// Remove 卸载模块
func (m *ModuleManager) Remove(id string) error {
	entries, _ := os.ReadDir(m.dir)
	for _, e := range entries {
		if p, err := loadFileModule(filepath.Join(m.dir, e.Name())); err == nil && p.ID == id {
			return os.Remove(filepath.Join(m.dir, e.Name()))
		}
	}
	return fmt.Errorf("未找到模块: %s", id)
}

func loadFileModule(path string) (*FileModule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var fm FileModule
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		if err := json.Unmarshal(data, &fm); err != nil {
			return nil, err
		}
	} else {
		if err := yaml.Unmarshal(data, &fm); err != nil {
			return nil, err
		}
	}
	if fm.ID == "" {
		return nil, fmt.Errorf("模块缺少 id")
	}
	return &fm, nil
}
