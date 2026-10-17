package netx

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

var (
	proxyMu     sync.RWMutex
	activeProxy string
)

// SetProxy 设置全局代理地址, 返回恢复函数(仅当设置未被后续覆盖时生效)
func SetProxy(u string) func() {
	proxyMu.Lock()
	prev := activeProxy
	activeProxy = u
	proxyMu.Unlock()
	return func() {
		proxyMu.Lock()
		if activeProxy == u {
			activeProxy = prev
		}
		proxyMu.Unlock()
	}
}

func getProxy() string {
	proxyMu.RLock()
	defer proxyMu.RUnlock()
	return activeProxy
}

// DialTimeout 通过可选的代理建立 TCP 连接(支持 socks5/http 代理)
func DialTimeout(addr string, timeout time.Duration) (net.Conn, error) {
	pu := getProxy()
	if pu == "" {
		return net.DialTimeout("tcp", addr, timeout)
	}
	u, err := url.Parse(pu)
	if err != nil {
		return nil, fmt.Errorf("无效代理地址 %q: %w", pu, err)
	}
	d, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		return nil, fmt.Errorf("代理初始化失败 %q: %w", pu, err)
	}
	if cd, ok := d.(proxy.ContextDialer); ok {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		return cd.DialContext(ctx, "tcp", addr)
	}
	return d.Dial("tcp", addr)
}

// tlsVerifyEnabled 由 NETSCAN_TLS_VERIFY=1 开启证书校验(默认跳过, 便于自签靶场)
func tlsVerifyEnabled() bool { return os.Getenv("NETSCAN_TLS_VERIFY") == "1" }

// sharedTransport 全局共享 HTTP Transport(连接池复用, 代理动态获取)
var sharedTransport = &http.Transport{
	TLSClientConfig: &tls.Config{InsecureSkipVerify: !tlsVerifyEnabled()},
	Proxy: func(req *http.Request) (*url.URL, error) {
		if pu := getProxy(); pu != "" {
			return url.Parse(pu)
		}
		return nil, nil
	},
}

// HTTPClient 创建带代理支持与连接复用的 HTTP 客户端
func HTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: sharedTransport}
}
