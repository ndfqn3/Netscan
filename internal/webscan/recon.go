package webscan

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Whois 查询域名 Whois 信息(跟随 IANA referral 到具体注册局)
func Whois(domain string, timeout time.Duration) (string, error) {
	first, err := whoisQuery("whois.iana.org:43", domain, timeout)
	if err != nil {
		return "", err
	}
	// 解析 referral, 查询具体注册局的 whois 服务器
	if ref := parseWhoisRefer(first); ref != "" {
		if second, err := whoisQuery(ref, domain, timeout); err == nil && second != "" {
			return second, nil
		}
	}
	return first, nil
}

// whoisQuery 向指定 whois 服务器查询域名
func whoisQuery(server, domain string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", server, timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(conn, "%s\r\n", domain)

	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return "", err
	}
	return string(buf[:n]), nil
}

// parseWhoisRefer 从 IANA 响应中解析 referral 的 whois 服务器地址
func parseWhoisRefer(resp string) string {
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "refer:") || strings.HasPrefix(lower, "whois:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				if ref := strings.TrimSpace(parts[1]); ref != "" {
					return ref
				}
			}
		}
	}
	return ""
}

// DNSRecords 查询域名的 DNS 记录
func DNSRecords(domain string, timeout time.Duration) map[string][]string {
	r := &net.Resolver{PreferGo: true}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	records := map[string][]string{}

	if ips, err := r.LookupHost(ctx, domain); err == nil {
		records["A/AAAA"] = ips
	}
	if cname, err := r.LookupCNAME(ctx, domain); err == nil && cname != "" && cname != domain+"." {
		records["CNAME"] = []string{strings.TrimSuffix(cname, ".")}
	}
	if mx, err := r.LookupMX(ctx, domain); err == nil {
		var list []string
		for _, m := range mx {
			list = append(list, fmt.Sprintf("%s (优先级 %d)", strings.TrimSuffix(m.Host, "."), m.Pref))
		}
		records["MX"] = list
	}
	if ns, err := r.LookupNS(ctx, domain); err == nil {
		var list []string
		for _, n := range ns {
			list = append(list, strings.TrimSuffix(n.Host, "."))
		}
		records["NS"] = list
	}
	if txt, err := r.LookupTXT(ctx, domain); err == nil {
		records["TXT"] = txt
	}
	return records
}
