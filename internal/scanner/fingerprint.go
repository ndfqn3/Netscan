package scanner

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// cmsRule CMS 指纹识别规则
type cmsRule struct {
	Name        string
	BodyRe      []string          // body 正则匹配
	VersionRe   string            // 版本号提取正则(捕获组 1)
	Cookies     []string          // cookie 名包含的子串
	HeaderSubs  map[string]string // 响应头包含的子串
	ExtraPath   string            // 额外探测路径
	ExtraBodyRe []string          // 额外路径 body 正则
}

var cmsRules = []cmsRule{
	{
		Name:      "WordPress",
		BodyRe:    []string{`wp-content`, `wp-includes`, `wp-json`, `name="generator" content="WordPress[^"]*"`},
		VersionRe: `WordPress ([0-9.]+)`,
		Cookies:   []string{"wordpress_", "wp-settings"},
	},
	{
		Name:      "Discuz",
		BodyRe:    []string{`Discuz!`, `Powered by Discuz!`, `discuz_uid`},
		VersionRe: `Discuz! ([X0-9.]+)`,
		Cookies:   []string{"discuz_", "dz_sid"},
	},
	{
		Name:       "ThinkPHP",
		BodyRe:     []string{`ThinkPHP`, `thinkphp`},
		VersionRe:  `ThinkPHP[^0-9]*([0-9.]+)`,
		HeaderSubs: map[string]string{"X-Powered-By": "ThinkPHP"},
	},
	{
		Name:      "DedeCMS",
		BodyRe:    []string{`Powered by DedeCMS`, `DedeCMS`, `/templets/default`},
		VersionRe: `DedeCMS V([0-9.]+)`,
	},
	{
		Name:      "Joomla",
		BodyRe:    []string{`Joomla!`, `com_content`},
		VersionRe: `Joomla! ([0-9.]+)`,
		Cookies:   []string{"joomla_"},
	},
	{
		Name:       "Drupal",
		BodyRe:     []string{`Drupal.settings`, `Drupal\.behaviors`},
		VersionRe:  `Drupal ([0-9.]+)`,
		HeaderSubs: map[string]string{"X-Generator": "Drupal"},
	},
	{
		Name:      "phpMyAdmin",
		BodyRe:    []string{`phpMyAdmin`, `pma_password`},
		VersionRe: `phpMyAdmin ([0-9.]+)`,
	},
	{
		Name:    "Laravel",
		Cookies: []string{"laravel_session", "XSRF-TOKEN"},
		BodyRe:  []string{`laravel`},
	},
	{
		Name:       "Shiro",
		Cookies:    []string{"rememberMe=deleteMe"},
		HeaderSubs: map[string]string{"Set-Cookie": "rememberMe="},
	},
	{
		Name:       "Spring Boot",
		BodyRe:     []string{`Whitelabel Error Page`, `Spring Boot`},
		HeaderSubs: map[string]string{"X-Application-Context": ""},
	},
	{
		Name:       "Tomcat",
		HeaderSubs: map[string]string{"Server": "Apache-Coyote"},
	},
	{
		Name:       "Nginx",
		HeaderSubs: map[string]string{"Server": "nginx"},
	},
	{
		Name:       "IIS",
		HeaderSubs: map[string]string{"Server": "Microsoft-IIS"},
	},
	{
		Name:      "phpBB",
		BodyRe:    []string{`Powered by phpBB`, `phpBB`},
		VersionRe: `phpBB ([0-9.]+)`,
	},
	{
		Name:      "MediaWiki",
		BodyRe:    []string{`MediaWiki`, `mw.config`},
		VersionRe: `MediaWiki ([0-9.]+)`,
	},
	{
		Name:   "EmpireCMS",
		BodyRe: []string{`Powered by EmpireCMS`, `EmpireCMS`},
	},
	{
		Name:   "SiteServer",
		BodyRe: []string{`SiteServer CMS`, `Powered by SiteServer`},
	},
}

// Fingerprint 对 HTTP/HTTPS 服务进行 CMS 指纹识别, 返回 "CMS 名称 版本"
func Fingerprint(ip string, port int, https bool, timeout time.Duration) string {
	scheme := "http"
	if https {
		scheme = "https"
	}
	base := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(ip, itoa(port)))
	client := httpClient(timeout)

	body, headers := fetchPage(client, base+"/", timeout)
	if body == "" && headers == nil {
		return ""
	}
	cookies := strings.Join(headerList(headers, "Set-Cookie"), "; ")

	for _, rule := range cmsRules {
		matched := false
		// 响应头特征
		for k, sub := range rule.HeaderSubs {
			if v := headerValue(headers, k); v != "" && (sub == "" || strings.Contains(v, sub)) {
				matched = true
				break
			}
		}
		// cookie 特征
		if !matched {
			for _, c := range rule.Cookies {
				if strings.Contains(cookies, c) {
					matched = true
					break
				}
			}
		}
		// body 特征
		if !matched {
			for _, re := range rule.BodyRe {
				if regexp.MustCompile(re).MatchString(body) {
					matched = true
					break
				}
			}
		}
		if !matched {
			continue
		}

		// 提取版本
		version := ""
		if rule.VersionRe != "" {
			if m := regexp.MustCompile(rule.VersionRe).FindStringSubmatch(body); m != nil && len(m) > 1 {
				version = m[1]
			}
		}
		if version != "" {
			return rule.Name + " " + version
		}
		return rule.Name
	}
	return ""
}

func fetchPage(client *http.Client, url string, timeout time.Duration) (string, http.Header) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) NetScan/2.0")
	resp, err := client.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return string(b), resp.Header
}

func headerValue(h http.Header, key string) string {
	return h.Get(key)
}

func headerList(h http.Header, key string) []string {
	return h.Values(key)
}
