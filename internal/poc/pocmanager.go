package poc

import (
	"fmt"
	"os"
	"path/filepath"
	"portscanner/internal/netx"
	"sort"
	"strings"
)

// POCManager 自定义 POC 管理
type POCManager struct {
	dir string
}

// DefaultPOCDir 自定义 POC 存储目录
func DefaultPOCDir() string {
	return netx.ResolveDataDir("pocs", ".netscan_pocs")
}

// OpenPOCManager 打开自定义 POC 管理
func OpenPOCManager(dir string) *POCManager {
	if dir == "" {
		dir = DefaultPOCDir()
	}
	_ = os.MkdirAll(dir, 0o755)
	return &POCManager{dir: dir}
}

// List 加载目录下所有自定义 POC 模板
func (m *POCManager) List() []POCTemplate {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return nil
	}
	var out []POCTemplate
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".json") {
			continue
		}
		t, err := LoadPOCTemplate(filepath.Join(m.dir, e.Name()))
		if err == nil && t != nil {
			out = append(out, *t)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Add 添加自定义 POC(复制文件到目录)
func (m *POCManager) Add(path string) error {
	t, err := LoadPOCTemplate(path)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dst := filepath.Join(m.dir, netx.SanitizeID(t.ID)+filepath.Ext(path))
	return os.WriteFile(dst, data, 0o644)
}

// Remove 按 ID 删除自定义 POC
func (m *POCManager) Remove(id string) error {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		path := filepath.Join(m.dir, e.Name())
		t, err := LoadPOCTemplate(path)
		if err == nil && t != nil && t.ID == id {
			return os.Remove(path)
		}
	}
	return fmt.Errorf("未找到 POC: %s", id)
}
