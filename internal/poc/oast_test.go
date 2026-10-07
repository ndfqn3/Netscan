package poc

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"portscanner/internal/netx"
)

// OAST 未启用时应跳过需要回调的模板
func TestOASTDisabled(t *testing.T) {
	tpl := POCTemplate{
		ID: "t-oast-off", Name: "test", Severity: "info", OAST: true,
		Requests: []POCRequest{{Method: "GET", Path: "/?u={{interactsh-url}}"}},
		Response: POCResponse{MatchersCondition: "or",
			Matchers: []POCMatcher{{Type: "oast", Words: []string{"http"}}}},
	}
	if r, _ := tpl.runWithBaseline("127.0.0.1", 1, time.Second, ""); r != "" {
		t.Fatalf("未启用回调时不应命中: %q", r)
	}
}

// OAST 端到端: 目标把注入的回调 URL 取回 -> 判定命中
func TestOASTCallback(t *testing.T) {
	if err := netx.StartOAST("127.0.0.1:0"); err != nil {
		t.Fatalf("启动回调服务失败: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if u := r.URL.Query().Get("u"); u != "" {
			if resp, err := http.Get(u); err == nil {
				resp.Body.Close()
			}
		}
		_, _ = w.Write([]byte("done"))
	}))
	defer srv.Close()
	uu, _ := url.Parse(srv.URL)
	port, _ := strconv.Atoi(uu.Port())

	tpl := POCTemplate{
		ID: "t-oast-on", Name: "test", Severity: "info", OAST: true,
		Requests: []POCRequest{{Method: "GET", Path: "/?u=http://{{interactsh-url}}"}},
		Response: POCResponse{MatchersCondition: "or",
			Matchers: []POCMatcher{{Type: "oast", Words: []string{"http"}}}},
	}
	r, _ := tpl.runWithBaseline("127.0.0.1", port, 5*time.Second, "")
	if r == "" {
		t.Fatal("回调已触发但未命中")
	}
}
