package poc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"portscanner/internal/netx"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// POCTemplate POC 模板(支持 YAML/JSON)
type POCTemplate struct {
	ID         string            `yaml:"id" json:"id"`
	Name       string            `yaml:"name" json:"name"`
	Service    string            `yaml:"service" json:"service"`
	Port       int               `yaml:"port" json:"port"`
	Severity   string            `yaml:"severity" json:"severity"`
	Variables  map[string]string `yaml:"variables" json:"variables"`   // 模板变量(支持 helper)
	Request    POCRequest        `yaml:"request" json:"request"`       // 兼容单请求模板
	Requests   []POCRequest      `yaml:"requests" json:"requests"`     // 多请求序列(raw/多 http 块)
	Extractors []POCExtractor    `yaml:"extractors" json:"extractors"` // 响应提取器(internal 作为后续请求变量)
	OAST       bool              `yaml:"oast" json:"oast"`             // 需要回调(interactsh-url)
	Response   POCResponse       `yaml:"response" json:"response"`
	Exploit    string            `yaml:"exploit" json:"exploit"`
}

// POCExtractor 响应提取器(nuclei 子集: regex/json/kval)
type POCExtractor struct {
	Name     string   `yaml:"name" json:"name"`
	Type     string   `yaml:"type" json:"type"`
	Regex    []string `yaml:"regex" json:"regex"`
	Group    int      `yaml:"group" json:"group"`
	JSON     []string `yaml:"json" json:"json"`
	KVal     []string `yaml:"kval" json:"kval"`
	Part     string   `yaml:"part" json:"part"`
	Internal bool     `yaml:"internal" json:"internal"`
}

// POCRequest 请求定义
type POCRequest struct {
	Proto     string            `yaml:"proto" json:"proto"` // http / tcp / udp, 默认 http
	Method    string            `yaml:"method" json:"method"`
	Path      string            `yaml:"path" json:"path"`
	Headers   map[string]string `yaml:"headers" json:"headers"`
	Body      string            `yaml:"body" json:"body"`
	Payload   string            `yaml:"payload" json:"payload"` // tcp/udp 原始 payload
	Raw       string            `yaml:"raw" json:"raw"`         // 原始 HTTP 请求文本(raw 模板)
	Redirects bool              `yaml:"redirects" json:"redirects"`
	Payloads  []POCPayload      `yaml:"payloads" json:"payloads"` // nuclei payloads(保序)
	Attack    string            `yaml:"attack" json:"attack"`     // clusterbomb(默认)/pitchfork/batteringram
}

// POCResponse 响应匹配
type POCResponse struct {
	// nuclei 风格匹配器(生成模板使用)
	MatchersCondition string       `yaml:"matchers_condition" json:"matchers_condition"`
	Matchers          []POCMatcher `yaml:"matchers" json:"matchers"`
	// 传统字段(手写模板兼容)
	Status   []int    `yaml:"status" json:"status"`
	Keywords []string `yaml:"keywords" json:"keywords"`
	Regex    []string `yaml:"regex" json:"regex"`
	JSONKeys []string `yaml:"json" json:"json"`
}

// POCMatcher 响应匹配器(nuclei 兼容子集)
type POCMatcher struct {
	Type            string   `yaml:"type" json:"type"` // status/word/regex/size/dsl/oast/oast_request
	Part            string   `yaml:"part" json:"part"` // body/header/all/body_N/content_type/location/response
	Words           []string `yaml:"words" json:"words"`
	Regex           []string `yaml:"regex" json:"regex"`
	Status          []int    `yaml:"status" json:"status"`
	Size            []int    `yaml:"size" json:"size"`
	DSL             []string `yaml:"dsl" json:"dsl"`
	Condition       string   `yaml:"condition" json:"condition"` // dsl 内部 and/or(默认 or)
	CaseInsensitive bool     `yaml:"case-insensitive" json:"case_insensitive"`
	Negative        bool     `yaml:"negative" json:"negative"`
}

// LoadPOCTemplate 从文件加载 POC 模板(自动识别 YAML/JSON)
func LoadPOCTemplate(path string) (*POCTemplate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	t := &POCTemplate{}
	lower := strings.ToLower(path)
	if strings.HasSuffix(lower, ".json") {
		err = json.Unmarshal(data, t)
	} else {
		err = yaml.Unmarshal(data, t)
	}
	if err != nil {
		return nil, fmt.Errorf("解析模板失败: %v", err)
	}
	if t.ID == "" {
		return nil, fmt.Errorf("模板缺少 id 字段")
	}
	return t, nil
}

// RunPOCTemplate 运行 POC 模板并返回结果描述(空表示未命中)
func (t *POCTemplate) RunPOCTemplate(target string, port int, timeout time.Duration) string {
	r, _ := t.runWithBaseline(target, port, timeout, "")
	return r
}

// Debugf 调试输出钩子(CLI --poc-debug / QC 使用)
var Debugf func(format string, args ...interface{})

// SetDebug 设置调试输出钩子
func SetDebug(f func(string, ...interface{})) { Debugf = f }

func debugf(format string, args ...interface{}) {
	if Debugf != nil {
		Debugf(format, args...)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// runWithBaseline 运行模板并返回(结果描述, 响应体)
// 支持多请求序列(raw/多 http 块): 依次发送, 任一响应命中即算命中(与 nuclei 默认一致)。
// baseline 非空时(软404基线): 响应键与基线一致则跳过该请求。
func (t *POCTemplate) runWithBaseline(target string, port int, timeout time.Duration, baseline string) (string, string) {
	if port <= 0 {
		port = t.Port
	}
	if port <= 0 {
		port = 80
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	reqs := t.Requests
	if len(reqs) == 0 {
		reqs = []POCRequest{t.Request}
	}
	token := ""
	oastURL := ""
	if t.OAST {
		if !netx.OASTEnabled() {
			return "", ""
		}
		token = netx.OASTNewToken()
		oastURL = netx.OASTURL(token)
	}
	rc := newRenderContext(t, target, port, oastURL)
	var resps []respRecord
	lastBody := ""
	reqIdx := 0
	for _, rq := range reqs {
		proto := rq.Proto
		if proto == "" {
			proto = "http"
		}
		for _, combo := range expandPayloads(rq) {
			rc.SetPayload(combo)
			reqIdx++
			t0 := time.Now()
			var respBody, respHeaders string
			var respStatus int
			switch proto {
			case "tcp", "udp":
				body, err := t.rawRequest(proto, rq, rc, timeout)
				if err != nil {
					continue
				}
				respBody, respStatus = body, 200
			default:
				body, headers, status, err := t.doHTTP(rq, rc, timeout)
				if err != nil {
					continue
				}
				respBody, respHeaders, respStatus = body, headers, status
			}
			elapsed := time.Since(t0)
			lastBody = respBody
			resps = append(resps, respRecord{body: respBody, headers: respHeaders, status: respStatus, duration: elapsed})
			debugf("[%s] req#%d proto=%s status=%d dur=%s body=%q", t.ID, reqIdx, proto, respStatus, elapsed.Round(time.Millisecond), truncate(respBody, 240))
			t.applyExtractors(rc, respBody, respHeaders)

			// 软404排除: 响应键与基线(随机路径)一致时视为误报
			if baseline != "" && netx.SameBaseline(baseline, netx.BaselineKey(respBody, rqPathR(rc, rq), rqBodyR(rc, rq), rqUA(rq))) {
				continue
			}
			oastInfo := oastResult{}
			if token != "" && t.hasOASTMatcher() {
				if ev, ok := netx.OASTWaitInfo(token, timeout); ok {
					oastInfo = oastResult{hit: true, protocol: ev.Protocol, request: ev.Request}
				}
			}
			if t.match(respBody, respHeaders, respStatus, oastInfo, rc, resps) {
				debugf("[%s] MATCH after req#%d", t.ID, reqIdx)
				sev := t.Severity
				if sev == "" {
					sev = "medium"
				}
				desc := t.Name
				if desc == "" {
					desc = t.ID
				}
				return fmt.Sprintf("[%s] %s: %s", sev, t.ID, desc), respBody
			}
		}
	}
	return "", lastBody
}

// firstLinePath 取 raw 请求首行中的路径
func firstLinePath(raw string) string {
	if i := strings.IndexByte(raw, '\n'); i > 0 {
		fields := strings.Fields(strings.TrimSpace(raw[:i]))
		if len(fields) >= 2 {
			return fields[1]
		}
	}
	return ""
}

// rawBody 取 raw 请求空行之后的内容
func rawBody(raw string) string {
	if i := strings.Index(raw, "\r\n\r\n"); i >= 0 {
		return raw[i+4:]
	}
	if i := strings.Index(raw, "\n\n"); i >= 0 {
		return raw[i+2:]
	}
	return ""
}

// rqPathR 渲染后的请求路径(raw 取首行中的目标)
func rqPathR(rc *renderContext, r POCRequest) string {
	if r.Raw != "" {
		return firstLinePath(rc.Render(r.Raw))
	}
	return rc.Render(r.Path)
}

// rqBodyR 渲染后的请求体
func rqBodyR(rc *renderContext, r POCRequest) string {
	if r.Raw != "" {
		return rawBody(rc.Render(r.Raw))
	}
	return rc.Render(r.Body)
}

// rqPath 取请求路径(raw 取首行中的目标)
func rqPath(r POCRequest) string {
	if r.Raw != "" {
		if i := strings.IndexByte(r.Raw, '\n'); i > 0 {
			fields := strings.Fields(strings.TrimSpace(r.Raw[:i]))
			if len(fields) >= 2 {
				return fields[1]
			}
		}
		return ""
	}
	return r.Path
}

// rqBody 取请求体(raw 取空行之后内容)
func rqBody(r POCRequest) string {
	if r.Raw != "" {
		if i := strings.Index(r.Raw, "\r\n\r\n"); i >= 0 {
			return r.Raw[i+4:]
		}
		if i := strings.Index(r.Raw, "\n\n"); i >= 0 {
			return r.Raw[i+2:]
		}
		return ""
	}
	return r.Body
}

// rqUA 取请求 User-Agent
func rqUA(r POCRequest) string {
	if r.Headers != nil {
		return r.Headers["User-Agent"]
	}
	return ""
}

// rqMethod 取请求方法(raw 取首行)
func rqMethod(r POCRequest) string {
	if r.Raw != "" {
		if i := strings.IndexByte(r.Raw, '\n'); i > 0 {
			f := strings.Fields(strings.TrimSpace(r.Raw[:i]))
			if len(f) >= 1 {
				return f[0]
			}
		}
		return "GET"
	}
	if r.Method == "" {
		return "GET"
	}
	return r.Method
}

// firstRequest 取模板的首个请求(兼容单请求字段)
func (t *POCTemplate) firstRequest() POCRequest {
	if len(t.Requests) > 0 {
		return t.Requests[0]
	}
	return t.Request
}

// applyExtractors 应用响应提取器(internal 变量供后续请求/DSL 使用)
func (t *POCTemplate) applyExtractors(rc *renderContext, body, headers string) {
	for _, ex := range t.Extractors {
		if !ex.Internal || ex.Name == "" {
			continue
		}
		hay := pickPart(ex.Part, body, headers)
		switch strings.ToLower(ex.Type) {
		case "regex":
			for _, rp := range ex.Regex {
				rg, err := regexp.Compile(rc.Render(rp))
				if err != nil {
					continue
				}
				m := rg.FindStringSubmatch(hay)
				if len(m) == 0 {
					continue
				}
				g := ex.Group
				if g < 0 || g >= len(m) {
					if len(m) > 1 {
						g = 1
					} else {
						g = 0
					}
				}
				rc.SetDynamic(ex.Name, m[g])
				break
			}
		case "json":
			for _, jp := range ex.JSON {
				if v := jsonPathSimple(hay, jp); v != "" {
					rc.SetDynamic(ex.Name, v)
					break
				}
			}
		case "kval":
		kvalLoop:
			for _, k := range ex.KVal {
				for _, line := range strings.Split(hay, "\n") {
					line = strings.TrimRight(line, "\r")
					if i := strings.IndexAny(line, ":="); i > 0 {
						if strings.EqualFold(strings.TrimSpace(line[:i]), k) {
							rc.SetDynamic(ex.Name, strings.TrimSpace(line[i+1:]))
							break kvalLoop
						}
					}
				}
			}
		}
	}
}

// jsonPathSimple 简易 JSON 路径提取(.a.b / .a[0].b / $.a), 基于 encoding/json 逐层遍历, 失败返回空
func jsonPathSimple(s, path string) string {
	var root interface{}
	if err := json.Unmarshal([]byte(s), &root); err != nil {
		return ""
	}
	p := strings.TrimSpace(path)
	p = strings.TrimPrefix(p, "$")
	p = strings.TrimPrefix(p, ".")
	if p == "" {
		return jsonScalarString(root)
	}
	cur := root
	for _, seg := range strings.Split(p, ".") {
		if seg == "" {
			continue
		}
		name := seg
		idx := -1
		if i := strings.IndexByte(seg, '['); i >= 0 {
			if j := strings.IndexByte(seg, ']'); j > i {
				if n, err := strconv.Atoi(strings.TrimSpace(seg[i+1 : j])); err == nil {
					idx = n
				}
				name = seg[:i]
			}
		}
		if name != "" {
			m, ok := cur.(map[string]interface{})
			if !ok {
				return ""
			}
			v, ok := m[name]
			if !ok {
				return ""
			}
			cur = v
		}
		if idx >= 0 {
			arr, ok := cur.([]interface{})
			if !ok || idx >= len(arr) {
				return ""
			}
			cur = arr[idx]
		}
	}
	return jsonScalarString(cur)
}

func jsonScalarString(v interface{}) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		if x == float64(int64(x)) {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case json.Number:
		return x.String()
	default:
		b, err := json.Marshal(x)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

// jsonPathSimpleLegacy 旧实现(字符串搜索), 仅保留供对比
func jsonPathSimpleLegacy(s, path string) string {
	segs := strings.Split(strings.TrimPrefix(strings.TrimSpace(path), "."), ".")
	cur := s
	for si, seg := range segs {
		idx := 0
		if i := strings.IndexByte(seg, '['); i >= 0 {
			if j := strings.IndexByte(seg, ']'); j > i {
				idx, _ = strconv.Atoi(seg[i+1 : j])
				seg = seg[:i]
			}
		}
		pos := strings.Index(cur, `"`+seg+`"`)
		if pos < 0 {
			return ""
		}
		cur = cur[pos+len(seg)+2:]
		colon := strings.IndexByte(cur, ':')
		if colon < 0 {
			return ""
		}
		cur = strings.TrimSpace(cur[colon+1:])
		for i := 0; i < idx; i++ {
			depth, inStr, k := 0, false, 0
			for ; k < len(cur); k++ {
				c := cur[k]
				if inStr {
					if c == '\\' {
						k++
					} else if c == '"' {
						inStr = false
					}
					continue
				}
				switch c {
				case '"':
					inStr = true
				case '{', '[':
					depth++
				case '}', ']':
					depth--
				case ',':
					if depth == 0 {
						goto next
					}
				}
			}
		next:
			if k >= len(cur) {
				return ""
			}
			cur = strings.TrimSpace(cur[k+1:])
		}
		if si == len(segs)-1 {
			if len(cur) == 0 {
				return ""
			}
			if cur[0] == '"' {
				var b strings.Builder
				for i := 1; i < len(cur); i++ {
					if cur[i] == '\\' && i+1 < len(cur) {
						i++
						b.WriteByte(cur[i])
						continue
					}
					if cur[i] == '"' {
						break
					}
					b.WriteByte(cur[i])
				}
				return b.String()
			}
			end := strings.IndexAny(cur, ",}\n")
			if end < 0 {
				end = len(cur)
			}
			return strings.TrimSpace(cur[:end])
		}
	}
	return ""
}

// oastResult OAST 回调匹配上下文
type oastResult struct {
	hit      bool
	protocol string
	request  string
}

// respRecord 单次请求响应(供索引 DSL: status_code_1/body_2 等)
type respRecord struct {
	body     string
	headers  string
	status   int
	duration time.Duration
}

// match 响应匹配(headers 为原始响应头文本, 供 part:header 匹配)
func (t *POCTemplate) match(body, headers string, status int, oast oastResult, rc *renderContext, resps []respRecord) bool {
	// nuclei 风格匹配器
	if len(t.Response.Matchers) > 0 {
		andCond := strings.EqualFold(t.Response.MatchersCondition, "and")
		for _, m := range t.Response.Matchers {
			ok := m.eval(body, headers, status, oast, rc, resps)
			if m.Negative {
				ok = !ok
			}
			if andCond {
				if !ok {
					return false
				}
			} else if ok {
				return true
			}
		}
		return andCond
	}
	// 传统字段
	if len(t.Response.Status) > 0 {
		hit := false
		for _, s := range t.Response.Status {
			if s == status {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	for _, k := range t.Response.Keywords {
		if strings.Contains(body, k) {
			return true
		}
	}
	for _, re := range t.Response.Regex {
		// 用户自定义正则可能非法, 用 Compile 避免 panic
		if rg, err := regexp.Compile(re); err == nil && rg.MatchString(body) {
			return true
		}
	}
	for _, key := range t.Response.JSONKeys {
		if strings.Contains(body, `"`+key+`"`) || strings.Contains(body, key+":") {
			return true
		}
	}
	// 无匹配条件时, 状态码 200 即命中
	if len(t.Response.Status) == 0 && len(t.Response.Keywords) == 0 && len(t.Response.Regex) == 0 && len(t.Response.JSONKeys) == 0 {
		return status == 200
	}
	return false
}

// eval 执行单个匹配器(rc 用于渲染 matcher 内的 {{...}}; resps 供索引 DSL)
func (m POCMatcher) eval(body, headers string, status int, oast oastResult, rc *renderContext, resps []respRecord) bool {
	render := func(s string) string {
		if rc == nil {
			return s
		}
		return rc.Render(s)
	}
	hay := matcherHay(m.Part, body, headers, resps)
	switch strings.ToLower(m.Type) {
	case "status":
		for _, s := range m.Status {
			if s == status {
				return true
			}
		}
		return false
	case "word":
		for _, w := range m.Words {
			w = render(w)
			if m.CaseInsensitive {
				if strings.Contains(strings.ToLower(hay), strings.ToLower(w)) {
					return true
				}
			} else if strings.Contains(hay, w) {
				return true
			}
		}
		return false
	case "regex":
		for _, r := range m.Regex {
			if rg, err := regexp.Compile(render(r)); err == nil && rg.MatchString(hay) {
				return true
			}
		}
		return false
	case "size":
		n := len(body)
		for _, s := range m.Size {
			if s == n {
				return true
			}
		}
		return false
	case "dsl":
		exprs := make([]string, 0, len(m.DSL))
		for _, e := range m.DSL {
			exprs = append(exprs, rc.SubstituteDynamic(render(e)))
		}
		return evalDSL(exprs, m.Condition, body, headers, status, resps, oast)
	case "oast":
		if !oast.hit {
			return false
		}
		if len(m.Words) == 0 {
			return true
		}
		for _, w := range m.Words {
			lw := strings.ToLower(w)
			if lw == "http" || lw == "https" || lw == strings.ToLower(oast.protocol) {
				return true
			}
		}
		return false
	case "oast_request":
		if !oast.hit {
			return false
		}
		req := oast.request
		for _, w := range m.Words {
			if m.CaseInsensitive {
				if strings.Contains(strings.ToLower(req), strings.ToLower(w)) {
					return true
				}
			} else if strings.Contains(req, w) {
				return true
			}
		}
		for _, r := range m.Regex {
			if rg, err := regexp.Compile(r); err == nil && rg.MatchString(req) {
				return true
			}
		}
		return false
	}
	return false
}

// hasOASTMatcher 模板是否包含回调匹配器
func (t *POCTemplate) hasOASTMatcher() bool {
	for _, m := range t.Response.Matchers {
		if strings.EqualFold(m.Type, "oast") || strings.EqualFold(m.Type, "oast_request") {
			return true
		}
	}
	return false
}

// pickPart 取匹配目标文本
func pickPart(part, body, headers string) string {
	switch strings.ToLower(part) {
	case "header", "headers":
		return headers
	case "all":
		return headers + "\r\n" + body
	}
	return body
}

// evalDSL 执行 nuclei DSL 表达式子集
// 支持: status_code[_N] OP N / len(part[_N]) OP N / contains[_all|_any](part[_N], "..") /
//
//	regex("..", part[_N]) / ! / && / ||   (part = body/header/all, _N 为第 N 个响应)
func evalDSL(exprs []string, cond string, body, headers string, status int, resps []respRecord, oast oastResult) bool {
	if len(exprs) == 0 {
		return false
	}
	andCond := strings.EqualFold(cond, "and")
	for _, e := range exprs {
		ok := evalDSLExpr(e, body, headers, status, resps, oast)
		if andCond {
			if !ok {
				return false
			}
		} else if ok {
			return true
		}
	}
	return andCond
}

var (
	dslStatusCode = regexp.MustCompile(`(?i)^status_code(?:_(\d+))?\s*(==|!=|>=|<=|>|<)\s*(\d+)$`)
	dslDuration   = regexp.MustCompile(`(?i)^duration(?:_(\d+))?\s*(==|!=|>=|<=|>|<)\s*(\d+)$`)
	dslLen        = regexp.MustCompile(`(?i)^len\((.*)\)\s*(==|!=|>=|<=|>|<)\s*(\d+)$`)
	dslRegex      = regexp.MustCompile(`(?i)^regex\((.*)\)$`)
	dslContains   = regexp.MustCompile(`(?i)^contains(_all|_any)?\((.*)\)$`)
	dslEq         = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_]*(?:\([^()]*\))?(?:_\d+)?)\s*(==|!=)\s*(\'[^\']*\'|"[^"]*")$`)
	dslStrEq      = regexp.MustCompile(`^(\'[^\']*\'|"[^"]*")\s*(==|!=)\s*(\'[^\']*\'|"[^"]*")$`)
)

// pickPartIndexed 按索引取 part 文本(索引 1 起, 0/越界用当前响应)
func pickPartIndexed(part string, idx int, body, headers string, resps []respRecord) string {
	if idx > 0 && idx <= len(resps) {
		r := resps[idx-1]
		if strings.EqualFold(part, "header") || strings.EqualFold(part, "headers") {
			return r.headers
		}
		return r.body
	}
	return pickPart(part, body, headers)
}

func evalDSLExpr(e string, body, headers string, status int, resps []respRecord, oast oastResult) bool {
	e = strings.TrimSpace(e)
	if e == "" {
		return false
	}
	if parts := splitTopLevel(e, "||"); len(parts) > 1 {
		for _, p := range parts {
			if evalDSLExpr(p, body, headers, status, resps, oast) {
				return true
			}
		}
		return false
	}
	if parts := splitTopLevel(e, "&&"); len(parts) > 1 {
		for _, p := range parts {
			if !evalDSLExpr(p, body, headers, status, resps, oast) {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(e, "!") && !strings.HasPrefix(e, "!=") {
		return !evalDSLExpr(e[1:], body, headers, status, resps, oast)
	}
	return evalDSLAtom(e, body, headers, status, resps, oast)
}

func evalDSLAtom(e string, body, headers string, status int, resps []respRecord, oast oastResult) bool {
	e = stripOuterParens(strings.TrimSpace(e))
	if m := dslStatusCode.FindStringSubmatch(e); m != nil {
		st := status
		if m[1] != "" {
			if idx, err := strconv.Atoi(m[1]); err == nil && idx > 0 && idx <= len(resps) {
				st = resps[idx-1].status
			}
		}
		n, _ := strconv.Atoi(m[3])
		return cmpInt(st, m[2], n)
	}
	if m := dslDuration.FindStringSubmatch(e); m != nil {
		dur := 0
		if m[1] != "" {
			if idx, err := strconv.Atoi(m[1]); err == nil && idx > 0 && idx <= len(resps) {
				dur = int(resps[idx-1].duration / time.Millisecond)
			}
		} else if len(resps) > 0 {
			dur = int(resps[len(resps)-1].duration / time.Millisecond)
		}
		n, _ := strconv.Atoi(m[3])
		return cmpInt(dur, m[2], n)
	}
	if m := dslLen.FindStringSubmatch(e); m != nil {
		txt, ok := partValue(m[1], body, headers, resps, oast)
		if !ok {
			return false
		}
		n, _ := strconv.Atoi(m[3])
		return cmpInt(len(txt), m[2], n)
	}
	if m := dslStrEq.FindStringSubmatch(e); m != nil {
		l, r := unquote(m[1]), unquote(m[3])
		if m[2] == "==" {
			return l == r
		}
		return l != r
	}
	if m := dslEq.FindStringSubmatch(e); m != nil {
		v, ok := partValue(m[1], body, headers, resps, oast)
		if !ok {
			return false
		}
		rhs := unquote(m[3])
		if m[2] == "==" {
			return v == rhs
		}
		return v != rhs
	}
	if m := dslRegex.FindStringSubmatch(e); m != nil {
		pat, part := parseRegexArgs(m[1])
		if pat == "" || part == "" {
			return false
		}
		v, ok := partValue(part, body, headers, resps, oast)
		if !ok {
			return false
		}
		rg, err := regexp.Compile(pat)
		return err == nil && rg.MatchString(v)
	}
	if m := dslContains.FindStringSubmatch(e); m != nil {
		args := splitTopLevel(m[2], ",")
		if len(args) < 2 {
			return false
		}
		hay, ok := partValue(args[0], body, headers, resps, oast)
		if !ok {
			return false
		}
		words := parseDSLArgs(strings.Join(args[1:], ","))
		if len(words) == 0 {
			return false
		}
		switch strings.ToLower(m[1]) {
		case "_all":
			for _, w := range words {
				if !strings.Contains(hay, w) {
					return false
				}
			}
			return true
		case "_any":
			for _, w := range words {
				if strings.Contains(hay, w) {
					return true
				}
			}
			return false
		default:
			return strings.Contains(hay, words[0])
		}
	}
	return false
}

// partValue 解析 part 表达式(body_2 / to_lower(header) / content_type / location /
//
//	response_2 / interactsh_protocol 等), 返回文本值
func partValue(partExpr, body, headers string, resps []respRecord, oast oastResult) (string, bool) {
	s := strings.TrimSpace(partExpr)
	lower, upper := false, false
	for {
		l := strings.ToLower(s)
		switch {
		case strings.HasPrefix(l, "to_lower(") && strings.HasSuffix(s, ")"):
			lower = true
			s = strings.TrimSpace(s[len("to_lower(") : len(s)-1])
		case strings.HasPrefix(l, "to_upper(") && strings.HasSuffix(s, ")"):
			upper = true
			s = strings.TrimSpace(s[len("to_upper(") : len(s)-1])
		default:
			goto done
		}
	}
done:
	s = strings.Trim(s, "() ")
	name, idx := s, 0
	if i := strings.LastIndexByte(s, '_'); i > 0 {
		if n, err := strconv.Atoi(s[i+1:]); err == nil {
			name, idx = s[:i], n
		}
	}
	name = strings.ToLower(strings.TrimSpace(name))
	var v string
	switch name {
	case "body", "header", "headers", "all":
		v = pickPartIndexed(name, idx, body, headers, resps)
	case "response":
		if idx > 0 && idx <= len(resps) {
			v = resps[idx-1].headers + "\r\n" + resps[idx-1].body
		} else {
			v = headers + "\r\n" + body
		}
	case "content_type", "content-type":
		if idx > 0 && idx <= len(resps) {
			v = headerValue(resps[idx-1].headers, "Content-Type")
		} else {
			v = headerValue(headers, "Content-Type")
		}
	case "location":
		if idx > 0 && idx <= len(resps) {
			v = headerValue(resps[idx-1].headers, "Location")
		} else {
			v = headerValue(headers, "Location")
		}
	case "interactsh_protocol":
		v = oast.protocol
	case "interactsh_request":
		v = oast.request
	case "oast":
		if oast.hit {
			v = "true"
		}
	default:
		return "", false
	}
	if lower {
		v = strings.ToLower(v)
	}
	if upper {
		v = strings.ToUpper(v)
	}
	return v, true
}

// matcherHay 计算 word/regex/size 匹配目标文本(支持索引与特殊 part)
func matcherHay(part, body, headers string, resps []respRecord) string {
	if part == "" {
		return body
	}
	if v, ok := partValue(part, body, headers, resps, oastResult{}); ok {
		return v
	}
	return pickPart(part, body, headers)
}

// headerValue 从原始响应头文本提取指定头的值
func headerValue(headers, name string) string {
	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimRight(line, "\r")
		if i := strings.IndexByte(line, ':'); i > 0 {
			if strings.EqualFold(strings.TrimSpace(line[:i]), name) {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

// unquote 去掉首尾引号
func unquote(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

// stripOuterParens 去掉完全包裹表达式的外层括号(允许任意层)
func stripOuterParens(e string) string {
	for len(e) >= 2 && e[0] == '(' && e[len(e)-1] == ')' {
		depth := 0
		ok := true
		for i := 0; i < len(e); i++ {
			switch e[i] {
			case '(':
				depth++
			case ')':
				depth--
				if depth == 0 && i != len(e)-1 {
					ok = false
				}
			}
			if !ok {
				break
			}
		}
		if !ok || depth != 0 {
			break
		}
		e = strings.TrimSpace(e[1 : len(e)-1])
	}
	return e
}

// parsePartToken 解析 part 文本(body_2 / (header_1)), 返回 (name, index, ok)
func parsePartToken(s string) (string, int, bool) {
	s = strings.TrimSpace(s)
	s = strings.Trim(s, "()")
	if i := strings.LastIndexByte(s, '_'); i > 0 {
		if n, err := strconv.Atoi(s[i+1:]); err == nil {
			name := strings.ToLower(s[:i])
			if name == "body" || name == "header" || name == "all" {
				return name, n, true
			}
		}
	}
	name := strings.ToLower(s)
	if name == "body" || name == "header" || name == "all" {
		return name, 0, true
	}
	return "", 0, false
}

// parseRegexArgs 解析 regex("pattern", part) 参数(part 可为非引号 token)
func parseRegexArgs(s string) (string, string) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", ""
	}
	i := strings.IndexAny(s, `'"`)
	if i < 0 {
		return "", ""
	}
	q := s[i]
	j := i + 1
	var sb strings.Builder
	for j < len(s) && s[j] != q {
		if s[j] == '\\' && j+1 < len(s) {
			j++
		}
		sb.WriteByte(s[j])
		j++
	}
	rest := ""
	if j < len(s) {
		rest = strings.TrimSpace(s[j+1:])
		rest = strings.TrimPrefix(rest, ",")
		rest = strings.TrimSpace(rest)
	}
	return sb.String(), rest
}

// splitTopLevel 按顶层运算符拆分(忽略括号与引号内的内容)
func splitTopLevel(e, op string) []string {
	var parts []string
	depth, start := 0, 0
	var quote byte
	for i := 0; i < len(e); {
		c := e[i]
		if quote != 0 {
			if c == '\\' {
				i += 2
				continue
			}
			if c == quote {
				quote = 0
			}
			i++
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			i++
		case '(':
			depth++
			i++
		case ')':
			depth--
			i++
		default:
			if depth == 0 && strings.HasPrefix(e[i:], op) {
				parts = append(parts, e[start:i])
				i += len(op)
				start = i
			} else {
				i++
			}
		}
	}
	parts = append(parts, e[start:])
	return parts
}

// parseDSLArgs 解析 DSL 函数参数字符串(仅支持引号字符串)
func parseDSLArgs(s string) []string {
	var out []string
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == ',') {
			i++
		}
		if i >= len(s) {
			break
		}
		q := s[i]
		if q != '\'' && q != '"' {
			return nil // 非字符串参数(变量等)不支持
		}
		i++
		var sb strings.Builder
		for i < len(s) && s[i] != q {
			if s[i] == '\\' && i+1 < len(s) {
				i++
			}
			sb.WriteByte(s[i])
			i++
		}
		if i >= len(s) {
			return nil
		}
		i++
		out = append(out, sb.String())
	}
	return out
}

func cmpInt(a int, op string, b int) bool {
	switch op {
	case "==":
		return a == b
	case "!=":
		return a != b
	case ">=":
		return a >= b
	case "<=":
		return a <= b
	case ">":
		return a > b
	case "<":
		return a < b
	}
	return false
}

// doHTTP 发送单个 HTTP 请求(普通或 raw), 返回 (响应体, 响应头文本, 状态码)
func (t *POCTemplate) doHTTP(rq POCRequest, rc *renderContext, timeout time.Duration) (string, string, int, error) {
	port := rc.port
	if rq.Raw != "" {
		return t.rawHTTP(rc.Render(rq.Raw), rc.target, port, timeout)
	}
	path := rc.Render(rq.Path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	method := rq.Method
	if method == "" {
		method = "GET"
	}
	url := fmt.Sprintf("http://%s%s", net.JoinHostPort(rc.target, netx.Itoa(port)), path)
	var bodyReader io.Reader
	if rq.Body != "" {
		bodyReader = strings.NewReader(rc.Render(rq.Body))
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return "", "", 0, err
	}
	req.Header.Set("User-Agent", "NetScan/4.0")
	for k, v := range rq.Headers {
		req.Header.Set(k, rc.Render(v))
	}
	client := netx.HTTPClient(timeout)
	if !rq.Redirects {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var hb strings.Builder
	hb.WriteString(resp.Proto + " " + resp.Status + "\r\n")
	for k, vs := range resp.Header {
		for _, v := range vs {
			hb.WriteString(k + ": " + v + "\r\n")
		}
	}
	return string(b), hb.String(), resp.StatusCode, nil
}

// rawHTTP 发送原始 HTTP 请求文本(raw 模板)
func (t *POCTemplate) rawHTTP(raw, target string, port int, timeout time.Duration) (string, string, int, error) {
	if !strings.Contains(raw, "\r\n\r\n") {
		raw = strings.ReplaceAll(raw, "\r\n", "\n")
		raw = strings.ReplaceAll(raw, "\n", "\r\n")
		if !strings.HasSuffix(raw, "\r\n") {
			raw += "\r\n"
		}
		raw += "\r\n"
	}
	raw = addContentLength(raw)
	addr := net.JoinHostPort(target, netx.Itoa(port))
	conn, err := netx.DialTimeout(addr, timeout)
	if err != nil {
		return "", "", 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(raw)); err != nil {
		return "", "", 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return "", "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var hb strings.Builder
	hb.WriteString(resp.Proto + " " + resp.Status + "\r\n")
	for k, vs := range resp.Header {
		for _, v := range vs {
			hb.WriteString(k + ": " + v + "\r\n")
		}
	}
	return string(b), hb.String(), resp.StatusCode, nil
}

// addContentLength 为缺少 Content-Length/Transfer-Encoding 的 raw 请求自动补充
// (与 nuclei rawhttp 行为一致; 否则 PUT/POST body 会被服务器忽略)
func addContentLength(raw string) string {
	idx := strings.Index(raw, "\r\n\r\n")
	if idx < 0 {
		return raw
	}
	head, body := raw[:idx], raw[idx+4:]
	if len(body) == 0 {
		return raw
	}
	low := strings.ToLower(head)
	if strings.Contains(low, "content-length") || strings.Contains(low, "transfer-encoding") {
		return raw
	}
	return head + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

// rawRequest 发送原始 tcp/udp 请求
func (t *POCTemplate) rawRequest(proto string, rq POCRequest, rc *renderContext, timeout time.Duration) (string, error) {
	payload := []byte(rc.Render(rq.Payload))
	addr := net.JoinHostPort(rc.target, netx.Itoa(rc.port))
	var conn net.Conn
	var err error
	if proto == "udp" {
		conn, err = net.DialTimeout("udp", addr, timeout)
	} else {
		conn, err = netx.DialTimeout(addr, timeout) // tcp 走代理
	}
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	if len(payload) > 0 {
		if _, err := conn.Write(payload); err != nil {
			return "", err
		}
	}
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	return string(buf[:n]), nil
}
