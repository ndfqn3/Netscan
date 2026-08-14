package scanner

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/semaphore"
)

// dirWordlist 内置目录/文件爆破字典(常见路径)
var dirWordlist = []string{
	"admin", "admin/", "admin.php", "admin.aspx", "admin.jsp", "admin/login",
	"administrator", "administrator/", "login", "login.php", "login.aspx", "login.jsp",
	"upload", "uploads", "upload/", "uploads/", "backup", "backup/", "backups/",
	"wp-admin", "wp-admin/", "wp-content", "wp-login.php", "wp-json",
	"robots.txt", "sitemap.xml", "favicon.ico", "crossdomain.xml",
	".git", ".git/config", ".svn", ".svn/entries", ".env", ".htaccess", ".htpasswd", ".DS_Store",
	"config.php", "config.inc.php", "configuration.php", "config.js", "config.json",
	"phpinfo.php", "info.php", "test.php", "test.html", "test.txt", "debug", "debug/",
	"index.php", "index.html", "index.htm", "index.asp", "index.aspx", "index.jsp",
	"default.asp", "default.aspx", "default.html", "home", "home/",
	"api", "api/", "api/v1", "api/v2", "api/users", "api/login",
	"server-status", "server-info", "status", "metrics", "health", "healthz",
	".well-known/security.txt", "security.txt",
	"console", "dashboard", "dashboard/", "panel", "panel/",
	"swagger-ui", "swagger-ui/", "swagger.json", "api-docs", "docs", "doc/",
	"cgi-bin", "cgi-bin/", "scripts", "scripts/", "js", "js/", "css", "css/", "images", "img",
	"tmp", "temp", "cache", "log", "logs", "log/", "logs/",
	"db", "database", "dump.sql", "backup.sql", "db.sql", "data", "data/",
	"download", "downloads", "file", "files", "files/",
	"phpmyadmin", "phpMyAdmin", "pma", "adminer.php", "adminer",
	"manager", "manager/", "manager/html", "actuator", "actuator/", "actuator/health",
	"jenkins", "jenkins/", "sonar", "sonar/", "grafana", "grafana/",
	"old", "old/", "new", "v1", "v2", "test", "tests", "beta",
	"private", "private/", "secret", "hidden", "internal",
	"shell", "shell.php", "cmd", "cmd.php", "1.php", "x.php",
	"readme", "readme.txt", "README.md", "changelog.txt", "license.txt",
	"user", "users", "account", "register", "signup", "signin", "auth",
	"search", "sitemap", "sitemap.xml", "rss", "feed", "atom.xml",
	"error", "error_log", "php_errors.log", "web.config", "web.xml",
	"composer.json", "package.json", "Gemfile", "Dockerfile", "docker-compose.yml",
	"src", "source", "bin", "lib", "include", "includes",
	".idea", ".vscode", ".gitignore", ".npmrc",
	"xmlrpc.php", "wp-cron.php", "wp-config.php", "wp-content/uploads",
	"j_security_check", "WEB-INF/web.xml", "META-INF", "axis2-admin",
	"solr", "solr/", "elastic", "kibana", "prometheus", "graphql",
	"api/graphql", "graphql/", "console/", "jmx-console", "invoker/JMXInvokerServlet",
}

// subdomainWordlist 内置子域名爆破字典
var subdomainWordlist = []string{
	"www", "mail", "smtp", "pop", "pop3", "imap", "ftp", "sftp",
	"webmail", "mx", "ns1", "ns2", "dns", "dns1", "dns2",
	"api", "api2", "dev", "develop", "test", "staging", "stage", "beta", "demo",
	"admin", "administrator", "manage", "management", "portal", "login", "sso",
	"app", "apps", "app1", "app2", "mobile", "m", "wap",
	"blog", "news", "forum", "bbs", "shop", "store", "mall", "pay", "payment",
	"static", "img", "images", "cdn", "assets", "media", "upload", "download", "file",
	"git", "gitlab", "svn", "jenkins", "ci", "build", "deploy", "ops", "monitor", "monitoring",
	"db", "database", "mysql", "redis", "mongo", "es", "elastic", "kibana", "grafana",
	"backup", "backups", "bak", "old", "old1", "new", "vpn", "remote", "rdp", "ssh",
	"vpn1", "vpn2", "gateway", "gw", "proxy", "firewall", "fw", "router",
	"secure", "security", "internal", "intranet", "local", "private", "hidden",
	"home", "cloud", "sync", "drive", "share", "nas", "files", "office", "oa",
	"erp", "crm", "hr", "mail2", "web", "web1", "web2", "www1", "www2",
}

// DirSearch 对目标 Web 服务进行目录/文件爆破
func DirSearch(host string, port int, https bool, concurrency int, timeout time.Duration, onFound func(path string, status int, size int64)) {
	if concurrency <= 0 {
		concurrency = 30
	}
	scheme := "http"
	if https {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, itoa(port)))

	client := httpClient(timeout)
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse // 不跟随重定向, 记录状态码
	}

	sem := semaphore.NewWeighted(int64(concurrency))
	var wg sync.WaitGroup
	for _, path := range dirWordlist {
		path := path
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = sem.Acquire(context.Background(), 1)
			defer sem.Release(1)

			url := base + "/" + path
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "NetScan/1.1 dirsearch")
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if interestingStatus(resp.StatusCode) {
				onFound(path, resp.StatusCode, resp.ContentLength)
			}
		}()
	}
	wg.Wait()
}

// interestingStatus 判定值得关注的 HTTP 状态码
func interestingStatus(code int) bool {
	switch code {
	case 200, 201, 202, 204, 301, 302, 307, 308, 400, 401, 403, 405, 500, 501, 502, 503:
		return true
	}
	return false
}

// HeaderIssue 安全头检查发现的问题
type HeaderIssue struct {
	Level   string // info / warn
	Message string
}

// WebHeaderCheck 检查 HTTP 响应头与安全配置
func WebHeaderCheck(host string, port int, https bool, timeout time.Duration) (map[string]string, []HeaderIssue) {
	scheme := "http"
	if https {
		scheme = "https"
	}
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(host, itoa(port)))

	client := httpClient(timeout)
	resp, err := client.Get(url)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	headers := map[string]string{}
	for k, v := range resp.Header {
		headers[k] = strings.Join(v, "; ")
	}

	var issues []HeaderIssue
	lower := map[string]string{}
	for k, v := range headers {
		lower[strings.ToLower(k)] = v
	}

	if _, ok := lower["x-frame-options"]; !ok {
		issues = append(issues, HeaderIssue{"warn", "缺少 X-Frame-Options 头(可被点击劫持)"})
	}
	if _, ok := lower["x-content-type-options"]; !ok {
		issues = append(issues, HeaderIssue{"info", "缺少 X-Content-Type-Options 头"})
	}
	if _, ok := lower["strict-transport-security"]; !ok {
		issues = append(issues, HeaderIssue{"info", "缺少 Strict-Transport-Security 头"})
	}
	if _, ok := lower["content-security-policy"]; !ok {
		issues = append(issues, HeaderIssue{"info", "缺少 Content-Security-Policy 头"})
	}
	if v, ok := lower["x-powered-by"]; ok {
		issues = append(issues, HeaderIssue{"info", "泄露 X-Powered-By: " + v})
	}
	if v, ok := lower["server"]; ok {
		issues = append(issues, HeaderIssue{"info", "泄露 Server: " + v})
	}
	return headers, issues
}

// SubdomainBrute 子域名爆破(广度优先, 支持反向 DNS 递归发现, 深度受 depth 限制)
func SubdomainBrute(domain string, depth int, concurrency int, timeout time.Duration, onFound func(sub string, ip string)) {
	if concurrency <= 0 {
		concurrency = 50
	}
	if depth < 1 {
		depth = 1
	}
	if depth > 3 {
		depth = 3
	}

	visited := map[string]bool{domain: true}
	queue := []string{domain}

	for level := 0; level < depth && len(queue) > 0; level++ {
		var mu sync.Mutex
		var next []string
		var wg sync.WaitGroup
		sem := semaphore.NewWeighted(int64(concurrency))

		for _, base := range queue {
			base := base
			for _, sub := range subdomainWordlist {
				sub := sub
				wg.Add(1)
				go func() {
					defer wg.Done()
					_ = sem.Acquire(context.Background(), 1)
					defer sem.Release(1)
					name := sub + "." + base
					ips, err := net.LookupHost(name)
					if err != nil || len(ips) == 0 {
						return
					}
					mu.Lock()
					if !visited[name] {
						visited[name] = true
						next = append(next, name)
					}
					mu.Unlock()
					onFound(name, ips[0])

					// 反向 DNS 发现新域名并入队
					if level < depth-1 {
						if rnames, err := net.LookupAddr(ips[0]); err == nil {
							for _, rn := range rnames {
								rn = strings.TrimSuffix(rn, ".")
								mu.Lock()
								if !visited[rn] {
									visited[rn] = true
									next = append(next, rn)
								}
								mu.Unlock()
							}
						}
					}
				}()
			}
		}
		wg.Wait()
		queue = next
	}
}
