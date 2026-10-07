package webscan

import (
	"net/http"
	"strings"
	"testing"
)

func TestWappTechs(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx")
	h.Set("X-Powered-By", "PHP/8.2.1")
	body := `<html><head><script src="/wp-includes/js/jquery/jquery.js"></script>` +
		`<meta name="generator" content="WordPress 6.4"></head><body></body></html>`
	got := wappTechs(h, body)
	if len(got) == 0 {
		t.Fatal("wappTechs 未识别出任何技术栈")
	}
	found := false
	for _, g := range got {
		if strings.Contains(strings.ToLower(g), "wordpress") {
			found = true
		}
	}
	if !found {
		t.Fatalf("未识别 WordPress: %v", got)
	}
	t.Logf("识别技术栈: %v", got)
}
