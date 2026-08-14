package scanner

import (
	"html/template"
	"os"
	"sort"
	"time"
)

// reportHost HTML 报告中的主机
type reportHost struct {
	IP       string
	Hostname string
	OS       string
	Ports    []reportPort
}

type reportPort struct {
	Port     int
	Protocol string
	State    string
	Service  string
	Version  string
	Vuln     string
}

type reportData struct {
	Title       string
	Target      string
	Ports       string
	Time        string
	TotalHosts  int
	OpenPorts   int
	VulnCount   int
	Hosts       []reportHost
}

const reportTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>NetScan 扫描报告</title>
<style>
  :root { --bg:#0b0f17; --card:#151c2b; --border:#22304a; --text:#e5e9f0; --muted:#8b98ab;
          --accent:#3b82f6; --green:#34d399; --red:#f87171; --amber:#fbbf24; }
  * { box-sizing:border-box; margin:0; padding:0; }
  body { font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif; background:var(--bg); color:var(--text); padding:24px; }
  h1 { font-size:22px; background:linear-gradient(90deg,var(--accent),#22d3ee); -webkit-background-clip:text; background-clip:text; color:transparent; }
  .meta { color:var(--muted); font-size:12px; margin:6px 0 16px; }
  .stats { display:flex; gap:12px; margin-bottom:18px; flex-wrap:wrap; }
  .stat { background:var(--card); border:1px solid var(--border); border-radius:10px; padding:12px 18px; min-width:120px; }
  .stat .n { font-size:24px; font-weight:700; color:var(--accent); }
  .stat .l { font-size:12px; color:var(--muted); }
  table { width:100%; border-collapse:collapse; font-size:13px; background:var(--card); border:1px solid var(--border); border-radius:8px; overflow:hidden; }
  th { text-align:left; padding:10px 12px; background:#1a2333; color:var(--muted); font-size:12px; border-bottom:1px solid var(--border); }
  td { padding:8px 12px; border-bottom:1px solid rgba(34,48,74,.5); }
  tr:nth-child(even) { background:rgba(255,255,255,.02); }
  .mono { font-family:Consolas,monospace; }
  .open { color:var(--green); } .vuln { color:var(--red); }
  .host-head { background:#1a2333; font-weight:700; }
</style>
</head>
<body>
<h1>NetScan 扫描报告</h1>
<div class="meta">目标: {{.Target}} &nbsp;|&nbsp; 端口: {{.Ports}} &nbsp;|&nbsp; 生成时间: {{.Time}}</div>
<div class="stats">
  <div class="stat"><div class="n">{{.TotalHosts}}</div><div class="l">存活主机</div></div>
  <div class="stat"><div class="n">{{.OpenPorts}}</div><div class="l">开放端口</div></div>
  <div class="stat"><div class="n">{{.VulnCount}}</div><div class="l">高危风险</div></div>
</div>
<table>
<tr><th>主机</th><th>端口</th><th>协议</th><th>状态</th><th>服务</th><th>版本</th><th>风险</th></tr>
{{range .Hosts}}
<tr class="host-head"><td class="mono" colspan="7">{{.IP}}{{if .Hostname}} ({{.Hostname}}){{end}}{{if .OS}} — {{.OS}}{{end}}</td></tr>
{{range .Ports}}
<tr><td></td><td class="mono">{{.Port}}</td><td>{{.Protocol}}</td><td class="open">{{.State}}</td><td>{{.Service}}</td><td>{{.Version}}</td><td class="vuln">{{.Vuln}}</td></tr>
{{end}}
{{end}}
</table>
</body>
</html>`

// WriteHTMLReport 生成自包含的暗色主题 HTML 报告
func WriteHTMLReport(path, target, ports string, results []Result) error {
	hostMap := map[string]*reportHost{}
	var order []string
	openPorts := 0
	vulnCount := 0

	for _, r := range results {
		switch r.State {
		case "up":
			if _, ok := hostMap[r.IP]; !ok {
				hostMap[r.IP] = &reportHost{IP: r.IP, Hostname: r.Hostname}
				order = append(order, r.IP)
			}
		case "os":
			if h, ok := hostMap[r.IP]; ok {
				h.OS = r.OS
			}
		case StateOpen:
			openPorts++
			if r.Vuln != "" {
				vulnCount++
			}
			h, ok := hostMap[r.IP]
			if !ok {
				h = &reportHost{IP: r.IP, Hostname: r.Hostname}
				hostMap[r.IP] = h
				order = append(order, r.IP)
			}
			h.Ports = append(h.Ports, reportPort{
				Port: r.Port, Protocol: r.Protocol, State: string(r.State),
				Service: r.Service, Version: r.Version, Vuln: r.Vuln,
			})
		}
	}

	sort.Strings(order)
	data := reportData{
		Title:      "NetScan 扫描报告",
		Target:     target,
		Ports:      ports,
		Time:       time.Now().Format("2006-01-02 15:04:05"),
		TotalHosts: len(order),
		OpenPorts:  openPorts,
		VulnCount:  vulnCount,
	}
	for _, ip := range order {
		h := hostMap[ip]
		sort.Slice(h.Ports, func(i, j int) bool { return h.Ports[i].Port < h.Ports[j].Port })
		data.Hosts = append(data.Hosts, *h)
	}

	tmpl, err := template.New("report").Parse(reportTemplate)
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return tmpl.Execute(f, data)
}
