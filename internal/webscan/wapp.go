package webscan

import (
	"net/http"
	"sort"
	"sync"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

// wappalyzergo (MIT) 技术栈指纹识别, 数据源 webappanalyzer/wappalyzer (MIT)
var (
	wappOnce sync.Once
	wappInst *wappalyzer.Wappalyze
)

func wappClient() *wappalyzer.Wappalyze {
	wappOnce.Do(func() {
		c, err := wappalyzer.New()
		if err == nil {
			wappInst = c
		}
	})
	return wappInst
}

// wappTechs 基于响应头+HTML 识别 Web 技术栈, 返回排序去重的技术名列表
func wappTechs(headers http.Header, body string) []string {
	c := wappClient()
	if c == nil || headers == nil && body == "" {
		return nil
	}
	fp := c.Fingerprint(map[string][]string(headers), []byte(body))
	if len(fp) == 0 {
		return nil
	}
	out := make([]string, 0, len(fp))
	for name := range fp {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
