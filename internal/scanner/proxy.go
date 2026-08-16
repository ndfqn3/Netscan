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

// sharedTransport 全局共享 HTTP Transport(连接池复用, 代理动态获取)
var sharedTransport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	Proxy: func(req *http.Request) (*url.URL, error) {
		if pu := getProxy(); pu != "" {
			return url.Parse(pu)
		}
		return nil, nil
	},
}

// httpClient 创建带代理支持与连接复用的 HTTP 客户端
func httpClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: sharedTransport}
}
