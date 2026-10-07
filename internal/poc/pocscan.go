package poc

import (
	"fmt"
	"os"
	"path/filepath"
	"portscanner/internal/netx"
	"sort"
	"strings"
	"sync"
	"time"
)

// ScanPOCs 批量扫描 Web POC 模板(nuclei 真实模板 + 用户自定义 + 额外模板列表),
// 额外列表由调用方注入(如插件 POC), 避免 poc 与 plugin 相互依赖。返回命中的漏洞。
func ScanPOCs(ip string, port int, timeout time.Duration, extra ...[]POCTemplate) []VulnHit {
	lists := [][]POCTemplate{nucleiPOCs, nucleiExtraPOCs, loadUserPOCs()}
	lists = append(lists, extra...)
	return scanLists(ip, port, timeout, lists)
}

// ScanPOCsFiltered 仅运行 id/name 含 filter(大小写不敏感)的内置模板, 用于定向验证
func ScanPOCsFiltered(ip string, port int, timeout time.Duration, filter string) []VulnHit {
	f := strings.ToLower(strings.TrimSpace(filter))
	var list []POCTemplate
	for _, t := range nucleiPOCs {
		if strings.Contains(strings.ToLower(t.ID), f) || strings.Contains(strings.ToLower(t.Name), f) {
			list = append(list, t)
		}
	}
	for _, t := range nucleiExtraPOCs {
		if strings.Contains(strings.ToLower(t.ID), f) || strings.Contains(strings.ToLower(t.Name), f) {
			list = append(list, t)
		}
	}
	return scanLists(ip, port, timeout, [][]POCTemplate{list})
}

func scanLists(ip string, port int, timeout time.Duration, lists [][]POCTemplate) []VulnHit {
	var hits []VulnHit
	var mu sync.Mutex

	// 软404基线: 记录随机路径响应的指纹(不限于 200), 排除
	// "任意路径返回同一错误页"的场景(如 Jenkins 全 403、Apache 404 页)。
	baseline := ""
	randPath := "/netscan-" + netx.RandomHex(6)
	if body, status := netx.HTTPDo(ip, port, "GET", randPath, "", "", timeout); status != 0 {
		baseline = netx.BaselineKey(body, randPath)
	}

	runList := func(list []POCTemplate) {
		sem := make(chan struct{}, 25)
		var wg sync.WaitGroup
		for _, tpl := range list {
			tpl := tpl
			wg.Add(1)
			sem <- struct{}{}
			go func() {
				defer wg.Done()
				defer func() { <-sem }()
				if r, _ := tpl.runWithBaseline(ip, port, timeout, baseline); r != "" {
					rq := tpl.firstRequest()
					hit := VulnHit{
						Name:  fmt.Sprintf("%s —— %s [%s]", tpl.ID, tpl.Name, tpl.Severity),
						Steps: fmt.Sprintf("%s %s", rqMethod(rq), ReproURL(ip, port, rqPath(rq))),
					}
					mu.Lock()
					hits = append(hits, hit)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
	}

	for _, list := range lists {
		runList(list)
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

// ReproURL 生成复现步骤 URL(补全前导斜杠)
func ReproURL(ip string, port int, path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return fmt.Sprintf("http://%s:%d%s", ip, port, path)
}
