package scanner

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

var (
	proxyMu     sync.RWMutex
	activeProxy string
)

// setProxy 设置全局代理地址(扫描开始时调用, 结束后清空)
func setProxy(u string) {
	proxyMu.Lock()
	activeProxy = u
	proxyMu.Unlock()
}

func getProxy() string {
	proxyMu.RLock()
	defer proxyMu.RUnlock()
	return activeProxy
}

// dialTimeout 通过可选的代理建立 TCP 连接(支持 socks5/http 代理)
func dialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	pu := getProxy()
	if pu == "" {
		return net.DialTimeout("tcp", addr, timeout)
	}
	u, err := url.Parse(pu)
	if err != nil {
		return net.DialTimeout("tcp", addr, timeout)
	}
	d, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		return net.DialTimeout("tcp", addr, timeout)
	}
	if cd, ok := d.(proxy.ContextDialer); ok {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return cd.DialContext(ctx, "tcp", addr)
	}
	return d.Dial("tcp", addr)
}

// httpClient 创建带代理支持的 HTTP 客户端
func httpClient(timeout time.Duration) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if pu := getProxy(); pu != "" {
		if u, err := url.Parse(pu); err == nil {
			tr.Proxy = http.ProxyURL(u)
		}
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}
