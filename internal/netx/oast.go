package netx

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// 内置 OAST 回调服务: 用于 SSRF/RCE 等外带检测模板。
// 目前捕获 HTTP 回调并保留原始请求内容(interactsh_request 语义);
// DNS/LDAP 等协议回调暂不支持。
type OASTEvent struct {
	Time     time.Time
	Protocol string // http(含 https 语义)
	Request  string // 原始请求文本(method/url/headers/body)
}

var (
	oastMu    sync.Mutex
	oastURL   string
	oastHits  map[string]OASTEvent
	oastSrv   *http.Server
	oastStart bool
)

// StartOAST 启动本地 HTTP 回调监听。advertise 为"目标可达的 host:port"
// (port 为 0 时自动分配端口, 实际端口会用于生成回调 URL)。
func StartOAST(advertise string) error {
	oastMu.Lock()
	defer oastMu.Unlock()
	if oastStart {
		return nil
	}
	host, port, err := net.SplitHostPort(advertise)
	if err != nil {
		return err
	}
	if host == "" {
		return fmt.Errorf("OAST 回调地址缺少 host: %q", advertise)
	}
	ln, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		return err
	}
	if port == "0" {
		if _, p, err2 := net.SplitHostPort(ln.Addr().String()); err2 == nil {
			port = p
		}
	}
	oastURL = "http://" + net.JoinHostPort(host, port)
	oastHits = map[string]OASTEvent{}
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.Trim(r.URL.Path, "/")
		if tok != "" {
			var sb strings.Builder
			sb.WriteString(r.Method + " " + r.RequestURI + " " + r.Proto + "\r\n")
			sb.WriteString("Host: " + r.Host + "\r\n")
			for k, vs := range r.Header {
				for _, v := range vs {
					sb.WriteString(k + ": " + v + "\r\n")
				}
			}
			b, _ := io.ReadAll(io.LimitReader(r.Body, 4096))
			if len(b) > 0 {
				sb.WriteString("\r\n")
				sb.Write(b)
			}
			recordOAST(tok, "http", sb.String())
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	oastSrv = &http.Server{Handler: mux}
	oastStart = true
	go func(srv *http.Server) {
		err := srv.Serve(ln)
		oastMu.Lock()
		defer oastMu.Unlock()
		if err != nil && err != http.ErrServerClosed {
			oastURL = ""
		}
		oastStart = false
		oastSrv = nil
	}(oastSrv)
	return nil
}

func recordOAST(token, proto, request string) {
	oastMu.Lock()
	defer oastMu.Unlock()
	if oastHits == nil {
		return
	}
	now := time.Now()
	for k, ev := range oastHits {
		if now.Sub(ev.Time) > 10*time.Minute {
			delete(oastHits, k)
		}
	}
	if len(oastHits) >= 1024 {
		for k := range oastHits {
			delete(oastHits, k)
			break
		}
	}
	if _, exists := oastHits[token]; !exists {
		oastHits[token] = OASTEvent{Time: now, Protocol: proto, Request: request}
	}
}

// OASTEnabled 是否已启用回调服务
func OASTEnabled() bool {
	oastMu.Lock()
	defer oastMu.Unlock()
	return oastStart
}

// OASTNewToken 生成回调 token
func OASTNewToken() string { return RandomHex(16) }

// OASTURL 生成注入到模板中的回调地址(nuclei 语义: 不带 scheme 的 host:port/token)
func OASTURL(token string) string {
	oastMu.Lock()
	defer oastMu.Unlock()
	if oastURL == "" {
		return ""
	}
	return strings.TrimPrefix(oastURL, "http://") + "/" + token
}

// OASTEventOf 取回调事件(含协议与原始请求)
func OASTEventOf(token string) (OASTEvent, bool) {
	if token == "" {
		return OASTEvent{}, false
	}
	oastMu.Lock()
	defer oastMu.Unlock()
	ev, ok := oastHits[token]
	return ev, ok
}

// OASTHit 回调是否已命中
func OASTHit(token string) bool {
	_, ok := OASTEventOf(token)
	return ok
}

// OASTWaitInfo 等待回调动静并返回事件(超时返回最后一次检查结果)
func OASTWaitInfo(token string, d time.Duration) (OASTEvent, bool) {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if ev, ok := OASTEventOf(token); ok {
			return ev, true
		}
		time.Sleep(150 * time.Millisecond)
	}
	ev, ok := OASTEventOf(token)
	return ev, ok
}

// OASTWait 等待回调动静(SSRF 等异步外带), 超时返回最后一次检查结果
func OASTWait(token string, d time.Duration) bool {
	_, ok := OASTWaitInfo(token, d)
	return ok
}
