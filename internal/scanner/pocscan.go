package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ScanPOCs 批量扫描 Web POC 模板(内置 + 用户自定义), 返回命中的漏洞
func ScanPOCs(ip string, port int, timeout time.Duration) []VulnHit {
	var hits []VulnHit

	// 内置 Web POC
	for _, p := range genWebPOCs {
		if r := p.RunPOCTemplate(ip, port, timeout); r != "" {
			hits = append(hits, VulnHit{
				Name:  fmt.Sprintf("%s —— %s [%s]", p.ID, p.Name, p.Severity),
				Steps: fmt.Sprintf("%s %s", methodOrGet(p.Request.Method), reproURL(ip, port, p.Request.Path)),
			})
		}
	}

	// 用户自定义 POC(pocs/ 目录)
	for _, p := range loadUserPOCs() {
		if r := p.RunPOCTemplate(ip, port, timeout); r != "" {
			hits = append(hits, VulnHit{
				Name:  fmt.Sprintf("%s —— %s [%s]", p.ID, p.Name, p.Severity),
				Steps: fmt.Sprintf("%s %s", methodOrGet(p.Request.Method), reproURL(ip, port, p.Request.Path)),
			})
		}
	}

	// 插件 POC(plugins/ 目录中启用状态的 poc/exploit 插件)
	for _, p := range OpenPluginManager("").POCs() {
		if r := p.RunPOCTemplate(ip, port, timeout); r != "" {
			hits = append(hits, VulnHit{
				Name:  fmt.Sprintf("%s —— %s [%s]", p.ID, p.Name, p.Severity),
				Steps: fmt.Sprintf("%s %s", methodOrGet(p.Request.Method), reproURL(ip, port, p.Request.Path)),
			})
		}
	}

	sort.Slice(hits, func(i, j int) bool { return hits[i].Name < hits[j].Name })
	return hits
}

// loadUserPOCs 从 pocs/ 目录加载用户自定义 POC 模板
func loadUserPOCs() []POCTemplate {
	var out []POCTemplate
	dir := DefaultPOCDir()
	if dir == "" {
		dir = "pocs"
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".json") {
			continue
		}
		if p, err := LoadPOCTemplate(filepath.Join(dir, e.Name())); err == nil {
			out = append(out, *p)
		}
	}
	return out
}

func methodOrGet(m string) string {
	if m == "" {
		return "GET"
	}
	return m
}

// reproURL 生成复现步骤 URL(补全前导斜杠)
func reproURL(ip string, port int, path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return fmt.Sprintf("http://%s:%d%s", ip, port, path)
}
