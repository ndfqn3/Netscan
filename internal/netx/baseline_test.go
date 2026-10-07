package netx

import "testing"

// CSRF/session 等页面对齐: 长随机串被剔除后, 同一兜底页应判定为基线一致
func TestBaselineKeyDynamicTokens(t *testing.T) {
	base := "<html><form><input name='csrf' value='AbCdEf0123456789AbCdEf0123456789AbCdEf'>" +
		"<a href='/login'>Login</a></form></html>"
	cand := "<html><form><input name='csrf' value='ZzYyXx9876543210ZzYyXx9876543210ZzYyXx'>" +
		"<a href='/login'>Login</a></form></html>"
	if BaselineKey(base, "/netscan-abcdef") != BaselineKey(cand, "/admin") {
		t.Fatal("含动态 CSRF token 的同一页面应归一化相等")
	}
	if BaselineKey(base, "/netscan-abcdef") == BaselineKey("<html><body>completely different</body></html>", "/admin") {
		t.Fatal("不同页面不应判定相等")
	}
}

// URL 编码回显请求路径的错误页: 两侧路径均被剔除 -> 相等
func TestBaselineKeyPathEcho(t *testing.T) {
	rand := "/netscan-123456"
	base := "<html>from=%2Fnetscan-123456 required</html>"
	cand := "<html>from=%2Fadmin%2F required</html>"
	if BaselineKey(base, rand) != BaselineKey(cand, "/admin/") {
		t.Fatal("编码回显路径的错误页应归一化相等")
	}
}

// 框架把路径作为 GET 参数回显(去前导斜杠)的调试/错误页 -> 相等
func TestBaselineKeyGetParamEcho(t *testing.T) {
	base := `<div class="code">$_GET=[&apos;p&apos;=&gt;&apos;netscan-abcdef&apos;];</div>`
	cand := `<div class="code">$_GET=[&apos;p&apos;=&gt;&apos;commands&apos;];</div>`
	if BaselineKey(base, "/netscan-abcdef") != BaselineKey(cand, "/commands") {
		t.Fatal("GET 参数回显路径的错误页应归一化相等")
	}
}
func TestBaselineKeyTimestamps(t *testing.T) {
	base := "Service Unavailable 2026-10-02T14:42:16.746086Z took 52397ms req-id=AbCdEf0123456789AbCdEf0123456789"
	cand := "Service Unavailable 2026-10-02T14:43:59.123456Z took 51234ms req-id=ZzYyXx9876543210ZzYyXx9876543210"
	if BaselineKey(base, "/netscan-abcdef") != BaselineKey(cand, "/actuator") {
		t.Fatal("含时间戳/耗时的同一错误页应归一化相等")
	}
}
