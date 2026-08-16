package scanner

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// POCTemplate POC 模板(支持 YAML/JSON)
type POCTemplate struct {
	ID       string      `yaml:"id" json:"id"`
	Name     string      `yaml:"name" json:"name"`
	Service  string      `yaml:"service" json:"service"`
	Port     int         `yaml:"port" json:"port"`
	Severity string      `yaml:"severity" json:"severity"`
	Request  POCRequest  `yaml:"request" json:"request"`
	Response POCResponse `yaml:"response" json:"response"`
	Exploit  string      `yaml:"exploit" json:"exploit"`
}

// POCRequest 请求定义
type POCRequest struct {
	Proto   string            `yaml:"proto" json:"proto"` // http / tcp / udp, 默认 http
	Method  string            `yaml:"method" json:"method"`
	Path    string            `yaml:"path" json:"path"`
	Headers map[string]string `yaml:"headers" json:"headers"`
	Body    string            `yaml:"body" json:"body"`
	Payload string            `yaml:"payload" json:"payload"` // tcp/udp 原始 payload
}

// POCResponse 响应匹配
type POCResponse struct {
	Status   []int    `yaml:"status" json:"status"`
	Keywords []string `yaml:"keywords" json:"keywords"`
	Regex    []string `yaml:"regex" json:"regex"`
	JSONKeys []string `yaml:"json" json:"json"`
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
	if port <= 0 {
		port = t.Port
	}
	if port <= 0 {
		port = 80
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	proto := t.Request.Proto
	if proto == "" {
		proto = "http"
	}

	var respBody string
	var respStatus int
	switch proto {
	case "tcp", "udp":
		var err error
		respBody, err = t.rawRequest(proto, target, port, timeout)
		if err != nil {
			return ""
		}
		respStatus = 200
	default:
		var err error
		respBody, respStatus, err = t.httpRequest(target, port, timeout)
		if err != nil {
			return ""
		}
	}

	if t.match(respBody, respStatus) {
		sev := t.Severity
		if sev == "" {
			sev = "medium"
		}
		desc := t.Name
		if desc == "" {
			desc = t.ID
		}
		return fmt.Sprintf("[%s] %s: %s", sev, t.ID, desc)
	}
	return ""
}

// match 响应匹配
func (t *POCTemplate) match(body string, status int) bool {
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

// httpRequest 发送 HTTP 请求
func (t *POCTemplate) httpRequest(target string, port int, timeout time.Duration) (string, int, error) {
	sub := t.vars(target, port)
	path := sub(t.Request.Path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	method := t.Request.Method
	if method == "" {
		method = "GET"
	}
	url := fmt.Sprintf("http://%s%s", net.JoinHostPort(target, itoa(port)), path)
	var bodyReader io.Reader
	if t.Request.Body != "" {
		bodyReader = strings.NewReader(sub(t.Request.Body))
	}
	req, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("User-Agent", "NetScan/4.0")
	for k, v := range t.Request.Headers {
		req.Header.Set(k, sub(v))
	}
	resp, err := httpClient(timeout).Do(req)
	if err != nil {
		return "", 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return string(b), resp.StatusCode, nil
}

// rawRequest 发送原始 tcp/udp 请求
func (t *POCTemplate) rawRequest(proto, target string, port int, timeout time.Duration) (string, error) {
	sub := t.vars(target, port)
	payload := []byte(sub(t.Request.Payload))
	addr := net.JoinHostPort(target, itoa(port))
	var conn net.Conn
	var err error
	if proto == "udp" {
		conn, err = net.DialTimeout("udp", addr, timeout)
	} else {
		conn, err = dialTimeout(addr, timeout) // tcp 走代理
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

// vars 返回变量替换函数
func (t *POCTemplate) vars(target string, port int) func(string) string {
	randStr := randomHex(8)
	return func(s string) string {
		r := strings.NewReplacer(
			"{{target}}", target,
			"{{port}}", strconv.Itoa(port),
			"{{randstr}}", randStr,
			"{{callback_host}}", "127.0.0.1",
			"{{callback_port}}", "4444",
		)
		return r.Replace(s)
	}
}

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
