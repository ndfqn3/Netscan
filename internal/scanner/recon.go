package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// Whois 查询域名 Whois 信息(通过 whois 服务器的 43 端口)
func Whois(domain string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("tcp", "whois.iana.org:43", timeout)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	fmt.Fprintf(conn, "%s\r\n", domain)

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return "", err
	}
	return string(buf[:n]), nil
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
