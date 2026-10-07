package poc

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math/rand"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"portscanner/internal/netx"
)

// POCPayload 请求级 payload 变量(nuclei payloads 的列表化表示, 保序)
type POCPayload struct {
	Name   string   `yaml:"name" json:"name"`
	Values []string `yaml:"values" json:"values"`
}

const (
	maxPayloadCombos = 256
	helperAlpha      = "abcdefghijklmnopqrstuvwxyz"
	helperUpper      = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	helperDigits     = "0123456789"
)

// builtinVar 内置占位符(与 nuclei 对齐)
func builtinVar(name, target string, port int, oastURL, randStr string) (string, bool) {
	host := net.JoinHostPort(target, strconv.Itoa(port))
	base := "http://" + host
	switch name {
	case "interactsh-url", "interactsh_url":
		if oastURL == "" {
			return "http://oast.invalid", true
		}
		return oastURL, true
	case "BaseURL", "RootURL":
		return base, true
	case "Hostname", "Host":
		return host, true
	case "Port":
		return strconv.Itoa(port), true
	case "Scheme":
		return "http", true
	case "target":
		return target, true
	case "port":
		return strconv.Itoa(port), true
	case "randstr":
		return randStr, true
	case "callback_host", "callback-url", "callback_url":
		return "127.0.0.1", true
	case "callback_port":
		return "4444", true
	}
	return "", false
}

// randFrom 从字符集生成随机串
func randFrom(n int, chars string) string {
	if n <= 0 {
		n = 8
	}
	if chars == "" {
		chars = helperAlpha + helperDigits
	}
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteByte(chars[rand.Intn(len(chars))])
	}
	return b.String()
}

// parseArgs 解析 helper 参数(逗号分隔, 引号可选)
func parseArgs(s string) []string {
	var out []string
	depth := 0
	var quote byte
	start := 0
	flush := func(end int) {
		v := strings.TrimSpace(s[start:end])
		v = strings.Trim(v, `"'`)
		out = append(out, v)
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				flush(i)
				start = i + 1
			}
		}
	}
	flush(len(s))
	return out
}

// evalHelper 执行 nuclei 风格 helper 表达式(不含 {{}}), 如 rand_int(1,100)
func evalHelper(expr string) (string, bool) {
	i := strings.IndexByte(expr, '(')
	if i <= 0 || !strings.HasSuffix(expr, ")") {
		return "", false
	}
	name := strings.ToLower(strings.TrimSpace(expr[:i]))
	args := parseArgs(expr[i+1 : len(expr)-1])
	atoi := func(s string, def int) int {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			return def
		}
		return n
	}
	switch name {
	case "rand_int":
		if len(args) != 2 {
			return "", false
		}
		a, b := atoi(args[0], 1), atoi(args[1], 100)
		if b < a {
			a, b = b, a
		}
		return strconv.Itoa(a + rand.Intn(b-a+1)), true
	case "rand_text_alpha", "rand_text":
		return randFrom(atoi(arg(args, 0), 8), helperAlpha+helperUpper), true
	case "rand_text_alphanumeric", "rand_base", "randbase":
		chars := helperAlpha + helperUpper + helperDigits
		if len(args) > 1 && args[1] != "" {
			chars = args[1]
		}
		return randFrom(atoi(arg(args, 0), 8), chars), true
	case "rand_text_numeric", "rand_number":
		return randFrom(atoi(arg(args, 0), 8), helperDigits), true
	case "rand_char":
		chars := helperAlpha + helperUpper + helperDigits
		if len(args) > 0 && args[0] != "" && atoi(args[0], 0) == 0 {
			chars = args[0]
		}
		return randFrom(1, chars), true
	case "to_lower":
		return strings.ToLower(arg(args, 0)), true
	case "to_upper":
		return strings.ToUpper(arg(args, 0)), true
	case "md5":
		h := md5.Sum([]byte(arg(args, 0)))
		return hex.EncodeToString(h[:]), true
	case "sha1":
		h := sha1.Sum([]byte(arg(args, 0)))
		return hex.EncodeToString(h[:]), true
	case "sha256":
		h := sha256.Sum256([]byte(arg(args, 0)))
		return hex.EncodeToString(h[:]), true
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(arg(args, 0))), true
	case "base64_decode":
		b, err := base64.StdEncoding.DecodeString(arg(args, 0))
		if err != nil {
			return "", false
		}
		return string(b), true
	case "hex_decode":
		b, err := hex.DecodeString(arg(args, 0))
		if err != nil {
			return "", false
		}
		return string(b), true
	case "url_encode", "urlencode":
		return url.QueryEscape(arg(args, 0)), true
	case "url_decode", "urldecode":
		v, err := url.QueryUnescape(arg(args, 0))
		if err != nil {
			return "", false
		}
		return v, true
	case "repeat":
		n := atoi(arg(args, 1), 1)
		if n < 0 {
			n = 0
		}
		if n > 4096 {
			n = 4096
		}
		return strings.Repeat(arg(args, 0), n), true
	case "unix_time":
		off := int64(0)
		if len(args) > 0 && args[0] != "" {
			off = int64(atoi(args[0], 0))
		}
		return strconv.FormatInt(time.Now().Unix()+off, 10), true
	case "trim_prefix":
		return strings.TrimPrefix(arg(args, 0), arg(args, 1)), true
	case "trim_suffix":
		return strings.TrimSuffix(arg(args, 0), arg(args, 1)), true
	case "concat":
		var sb strings.Builder
		for _, a := range args {
			sb.WriteString(a)
		}
		return sb.String(), true
	case "replace":
		return strings.ReplaceAll(arg(args, 0), arg(args, 1), arg(args, 2)), true
	case "to_number":
		return arg(args, 0), true
	case "len":
		return strconv.Itoa(len(arg(args, 0))), true
	}
	return "", false
}

func arg(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

// renderContext 运行时渲染上下文(变量/助手/payload 替换)
type renderContext struct {
	t       *POCTemplate
	target  string
	port    int
	oastURL string
	randStr string
	extra   map[string]string
	dynamic map[string]string // 内部 extractor 提取的动态变量
	cache   map[string]string
}

func newRenderContext(t *POCTemplate, target string, port int, oastURL string) *renderContext {
	return &renderContext{
		t: t, target: target, port: port, oastURL: oastURL,
		randStr: netx.RandomHex(8),
		dynamic: map[string]string{},
		cache:   map[string]string{},
	}
}

// SetDynamic 设置内部提取器得到的动态变量
func (rc *renderContext) SetDynamic(name, value string) {
	if name != "" {
		rc.dynamic[name] = value
	}
}

// SubstituteDynamic 把 DSL 中的裸动态变量名替换为带引号的值
func (rc *renderContext) SubstituteDynamic(expr string) string {
	if rc == nil || len(rc.dynamic) == 0 {
		return expr
	}
	for k, v := range rc.dynamic {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(k) + `\b`)
		expr = re.ReplaceAllString(expr, `'`+strings.ReplaceAll(v, `'`, `\'`)+`'`)
	}
	return expr
}

// SetPayload 设置当前 payload 组合(模板变量缓存跨请求保持稳定, 与 nuclei 一致)
func (rc *renderContext) SetPayload(extra map[string]string) {
	rc.extra = extra
}

// Render 渲染字符串: 内置占位符/模板变量/helper/payload, 未知原样保留(兼容 SSTI 注入)
func (rc *renderContext) Render(s string) string {
	return rc.render(s, 0)
}

func (rc *renderContext) render(s string, depth int) string {
	if depth > 8 || !strings.Contains(s, "{{") {
		return s
	}
	var b strings.Builder
	for {
		i := strings.Index(s, "{{")
		if i < 0 {
			b.WriteString(s)
			break
		}
		j := strings.Index(s[i+2:], "}}")
		if j < 0 {
			b.WriteString(s)
			break
		}
		b.WriteString(s[:i])
		b.WriteString(rc.eval(s[i+2:i+2+j], depth))
		s = s[i+2+j+2:]
	}
	return b.String()
}

func (rc *renderContext) eval(expr string, depth int) string {
	ex := strings.TrimSpace(expr)
	if v, ok := builtinVar(ex, rc.target, rc.port, rc.oastURL, rc.randStr); ok {
		return v
	}
	if rc.extra != nil {
		if v, ok := rc.extra[ex]; ok {
			return v
		}
	}
	if rc.dynamic != nil {
		if v, ok := rc.dynamic[ex]; ok {
			return v
		}
	}
	if rc.t.Variables != nil {
		if raw, ok := rc.t.Variables[ex]; ok {
			if v, ok := rc.cache[ex]; ok {
				return v
			}
			v := rc.render(raw, depth+1)
			rc.cache[ex] = v
			return v
		}
	}
	if v, ok := evalHelper(ex); ok {
		return v
	}
	return "{{" + expr + "}}"
}

// expandPayloads 按 attack 模式展开 payload 组合(上限 maxPayloadCombos)
// clusterbomb: 笛卡尔积; pitchfork: 各变量按位置并行; batteringram: 首变量值铺满全部变量
func expandPayloads(rq POCRequest) []map[string]string {
	if len(rq.Payloads) == 0 {
		return []map[string]string{nil}
	}
	attack := strings.ToLower(strings.TrimSpace(rq.Attack))
	switch attack {
	case "pitchfork":
		n := -1
		for _, p := range rq.Payloads {
			if n < 0 || len(p.Values) < n {
				n = len(p.Values)
			}
		}
		if n <= 0 {
			return []map[string]string{nil}
		}
		if n > maxPayloadCombos {
			n = maxPayloadCombos
		}
		out := make([]map[string]string, 0, n)
		for i := 0; i < n; i++ {
			m := map[string]string{}
			for _, p := range rq.Payloads {
				m[p.Name] = p.Values[i]
			}
			out = append(out, m)
		}
		return out
	case "batteringram":
		vals := rq.Payloads[0].Values
		if len(vals) == 0 {
			return []map[string]string{nil}
		}
		out := make([]map[string]string, 0, len(vals))
		for _, v := range vals {
			if len(out) >= maxPayloadCombos {
				break
			}
			m := map[string]string{}
			for _, p := range rq.Payloads {
				m[p.Name] = v
			}
			out = append(out, m)
		}
		return out
	default: // clusterbomb
		combos := []map[string]string{{}}
		for _, p := range rq.Payloads {
			if len(p.Values) == 0 {
				continue
			}
			next := make([]map[string]string, 0, len(combos)*len(p.Values))
		outer:
			for _, c := range combos {
				for _, v := range p.Values {
					m := make(map[string]string, len(c)+1)
					for k, vv := range c {
						m[k] = vv
					}
					m[p.Name] = v
					next = append(next, m)
					if len(next) >= maxPayloadCombos {
						break outer
					}
				}
			}
			combos = next
		}
		return combos
	}
}
