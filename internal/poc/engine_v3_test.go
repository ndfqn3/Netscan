package poc

import (
	"strings"
	"testing"
	"time"
)

func TestExpandPayloads(t *testing.T) {
	rq := POCRequest{Payloads: []POCPayload{
		{Name: "a", Values: []string{"1", "2"}},
		{Name: "b", Values: []string{"x", "y"}},
	}}
	c := expandPayloads(rq)
	if len(c) != 4 {
		t.Fatalf("clusterbomb=%d want 4", len(c))
	}
	rq.Attack = "pitchfork"
	p := expandPayloads(rq)
	if len(p) != 2 || p[1]["a"] != "2" || p[1]["b"] != "y" {
		t.Fatalf("pitchfork=%v", p)
	}
	rq.Attack = "batteringram"
	b := expandPayloads(rq)
	if len(b) != 2 || b[1]["a"] != "2" || b[1]["b"] != "2" {
		t.Fatalf("batteringram=%v", b)
	}
	big := POCRequest{Payloads: []POCPayload{{Name: "x", Values: make([]string, 300)}}}
	for i := range big.Payloads[0].Values {
		big.Payloads[0].Values[i] = "v"
	}
	if len(expandPayloads(big)) > maxPayloadCombos {
		t.Fatal("payload combos not capped")
	}
}

func TestRenderHelpers(t *testing.T) {
	tpl := &POCTemplate{Variables: map[string]string{
		"n":    "{{to_upper(abc)}}",
		"self": "x{{n}}",
	}}
	rc := newRenderContext(tpl, "10.0.0.1", 8080, "oast.local/tok")
	got := rc.Render("{{to_lower(ABC)}}|{{md5(test)}}|{{n}}|{{self}}|{{unknown}}|{{BaseURL}}|{{randstr}}")
	parts := strings.Split(got, "|")
	if parts[0] != "abc" {
		t.Fatalf("to_lower: %q", parts[0])
	}
	if parts[1] != "098f6bcd4621d373cade4e832627b4f6" {
		t.Fatalf("md5: %q", parts[1])
	}
	if parts[2] != "ABC" || parts[3] != "xABC" {
		t.Fatalf("template vars: %q %q", parts[2], parts[3])
	}
	if parts[4] != "{{unknown}}" {
		t.Fatalf("unknown passthrough: %q", parts[4])
	}
	if parts[5] != "http://10.0.0.1:8080" {
		t.Fatalf("BaseURL: %q", parts[5])
	}
	if len(parts[6]) != 16 {
		t.Fatalf("randstr: %q", parts[6])
	}
	if rc.Render("{{randstr}}") != parts[6] {
		t.Fatal("randstr should be stable within one run")
	}
	if v := rc.Render("{{rand_int(5,5)}}"); v != "5" {
		t.Fatalf("rand_int fixed: %q", v)
	}
}

func TestDSLIndexedAndParts(t *testing.T) {
	resps := []respRecord{
		{body: "one", headers: "HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n", status: 403, duration: 5 * time.Millisecond},
		{body: "two OK meta", headers: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nLocation: /index.action\r\n", status: 200, duration: 20 * time.Millisecond},
	}
	cases := []struct {
		expr string
		want bool
	}{
		{"status_code_1 == 403", true},
		{"status_code_2 == 200", true},
		{"contains(body_2, 'OK')", true},
		{"contains(location_2, '/index.action')", true},
		{"contains(content_type_2, 'application/json')", true},
		{"duration >= 10", true},
		{"body_2 == 'two OK meta'", true},
		{`regex('[a-z]{3}', body_1)`, true},
		{`((regex('one', body_1)))`, true},
		{"((status_code_1 == 403))", true},
		{"contains((body_2), 'nope')", false},
	}
	for _, c := range cases {
		if got := evalDSL([]string{c.expr}, "and", "cur", "", 0, resps, oastResult{}); got != c.want {
			t.Fatalf("dsl %q = %v want %v", c.expr, got, c.want)
		}
	}
	if !evalDSL([]string{`contains(interactsh_protocol, "http")`}, "and", "", "", 0, nil,
		oastResult{hit: true, protocol: "http"}) {
		t.Fatal("interactsh_protocol dsl")
	}
}

func TestDynamicVarDSL(t *testing.T) {
	tpl := &POCTemplate{Response: POCResponse{Matchers: []POCMatcher{
		{Type: "dsl", DSL: []string{"x_vuln_check != ''"}},
	}}}
	rc := newRenderContext(tpl, "h", 80, "")
	if tpl.match("", "", 200, oastResult{}, rc, nil) {
		t.Fatal("empty dynamic var should not match ne-empty")
	}
	rc.SetDynamic("x_vuln_check", "abc")
	if !tpl.match("", "", 200, oastResult{}, rc, nil) {
		t.Fatal("dynamic var dsl should match")
	}
}

func TestMatcherRenderAndNegative(t *testing.T) {
	tpl := &POCTemplate{Response: POCResponse{MatchersCondition: "and", Matchers: []POCMatcher{
		{Type: "word", Words: []string{"{{randstr}}"}},
		{Type: "word", Words: []string{"absent"}, Negative: true},
	}}}
	rc := newRenderContext(tpl, "h", 80, "")
	body := "prefix " + rc.randStr + " suffix"
	if !tpl.match(body, "", 200, oastResult{}, rc, nil) {
		t.Fatal("rendered randstr matcher should hit")
	}
	tpl2 := &POCTemplate{Response: POCResponse{Matchers: []POCMatcher{
		{Type: "oast_request", Words: []string{"User-Agent: Java"}, CaseInsensitive: true},
	}}}
	req := "GET /x HTTP/1.1\r\nUser-Agent: Java/1.8\r\n"
	if !tpl2.match("", "", 200, oastResult{hit: true, protocol: "http", request: req}, rc, nil) {
		t.Fatal("oast_request matcher")
	}
}
