package netx

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Itoa 整数转字符串(含负数)
func Itoa(n int) string {
	return strconv.Itoa(n)
}

// RandomHex 生成 n 字节随机数的十六进制串(软404基线路径等使用)
func RandomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// NormalizeBody 归一化响应体(去除指定子串并压缩空白), 用于软404基线比对。
// 错误页常以 URL 编码/HTML 转义形式回显请求路径, 因此同时剔除这些变体。
func NormalizeBody(s string, drop ...string) string {
	for _, d := range drop {
		if d == "" {
			continue
		}
		variants := []string{
			d,
			url.QueryEscape(d),                // /admin/ -> %2Fadmin%2F
			strings.ReplaceAll(d, "/", "%2F"), // 大写编码形式
			html.EscapeString(d),              // & -> &amp;
		}
		if i := strings.IndexByte(d, '?'); i >= 0 {
			variants = append(variants, d[:i]) // 错误页常只回显去查询串的路径
		}
		for _, v := range variants {
			if v != "" {
				s = strings.ReplaceAll(s, v, "")
			}
		}
	}
	return strings.Join(strings.Fields(s), "")
}

// reLongRandom 匹配每次响应都会变化的长随机串(CSRF token/session id/nonce/nonce hash 等)
var reLongRandom = regexp.MustCompile(`[A-Za-z0-9+/=_-]{24,}`)

// reDigits 匹配数字: 错误页里的时间戳/耗时/端口/请求 ID 等每次响应不同
var reDigits = regexp.MustCompile(`[0-9]+`)

// BaselineKey 生成用于软404基线比对的响应"键"(对称处理, 两侧算法一致):
//   - 去掉所有含 '%' 的空白 token: 错误页常以 URL 编码整段回显请求路径,
//     且不同服务器编码形式各异(Jenkins %2F..%3F.., 甚至二次编码);
//   - 去掉该请求路径原文(含去查询串形式, 前缀太短则跳过避免误删);
//   - 去掉长随机串(页面里的 CSRF/session token 每次响应不同, 否则基线永远不相等);
//   - 压缩空白。
func BaselineKey(body, path string, extraDrop ...string) string {
	var kept []string
	for _, tok := range strings.Fields(body) {
		if strings.Contains(tok, "%") {
			continue
		}
		kept = append(kept, tok)
	}
	s := strings.Join(kept, " ")
	drops := append([]string{}, extraDrop...)
	if path != "" {
		// 同时剔除带/不带前导斜杠的路径(框架常把路径作为 GET 参数回显, 如 Yii p=netscan-xxx)
		drops = append(drops, path, strings.TrimPrefix(path, "/"))
		if i := strings.IndexByte(path, '?'); i >= 0 {
			drops = append(drops, path[:i], strings.TrimPrefix(path[:i], "/"))
			if i+1 < len(path) {
				// 调试/错误页常回显 query 串与各参数值
				q := path[i+1:]
				drops = append(drops, q, "?"+q, "&"+q)
				for _, kv := range strings.Split(q, "&") {
					if j := strings.IndexByte(kv, '='); j >= 0 && j+1 < len(kv) {
						drops = append(drops, kv[j+1:])
					}
				}
			}
		}
	}
	for _, d := range drops {
		if d == "" || d == "/" {
			continue
		}
		s = strings.ReplaceAll(s, d, "")
		// 服务端可能回显 URL 解码后的路径/参数值
		if u, err := url.QueryUnescape(d); err == nil && u != d {
			s = strings.ReplaceAll(s, u, "")
		}
	}
	s = reLongRandom.ReplaceAllString(s, "")
	s = reDigits.ReplaceAllString(s, "")
	return strings.Join(strings.Fields(s), "")
}

// ReadAll 读取响应体(上限 64KB, 防止恶意大响应耗尽内存)
func ReadAll(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 64*1024))
	return string(b)
}

// HTTPDo 发送 HTTP 请求并返回响应体与状态码
func HTTPDo(ip string, port int, method, path, body, contentType string, timeout time.Duration) (string, int) {
	return HTTPDoHeaders(ip, port, method, path, body, contentType, nil, timeout)
}

// HTTPDoHeaders 发送 HTTP 请求(支持自定义请求头)并返回响应体与状态码
func HTTPDoHeaders(ip string, port int, method, path, body, contentType string, headers map[string]string, timeout time.Duration) (string, int) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	urlStr := fmt.Sprintf("http://%s%s", net.JoinHostPort(ip, Itoa(port)), path)
	return DoHTTPReq(HTTPClient(timeout), method, urlStr, body, contentType, headers)
}

// DoHTTPReq 使用指定客户端发送 HTTP 请求(支持自定义请求头, 可复用带 cookie jar 的客户端)
func DoHTTPReq(client *http.Client, method, urlStr, body, contentType string, headers map[string]string) (string, int) {
	req, err := http.NewRequest(method, urlStr, strings.NewReader(body))
	if err != nil {
		return "", 0
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", "NetScan/3.0")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", 0
	}
	defer resp.Body.Close()
	b := ReadAll(resp.Body)
	return b, resp.StatusCode
}

// HTTPGet 简单 HTTP GET(响应体上限 8KB), 供 POC/利用链复用
func HTTPGet(ip string, port int, path string, timeout time.Duration) (string, error) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	url := fmt.Sprintf("http://%s%s", net.JoinHostPort(ip, Itoa(port)), path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "NetScan/2.0 poc")
	resp, err := HTTPClient(timeout).Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	return string(b), nil
}

// SameBaseline 判断候选响应键是否与软404基线一致(精确相等或高度相似)。
// 高相似度判定用于容忍少量请求回显差异(短路径子串、UA、栈帧等),
// 同时仍能排除与基线明显不同的真实响应。
func SameBaseline(baseline, candidate string) bool {
	if baseline == "" || candidate == "" {
		return baseline == candidate
	}
	if baseline == candidate {
		return true
	}
	return similarShingles(baseline, candidate, 0.95)
}

// similarShingles 以 k 字符滑窗集合的 Jaccard 相似度判断两文本是否高度相似
func similarShingles(a, b string, threshold float64) bool {
	const k = 16
	if len(a) < k || len(b) < k {
		return false
	}
	setA := make(map[string]struct{}, len(a))
	for i := 0; i+k <= len(a); i++ {
		setA[a[i:i+k]] = struct{}{}
	}
	inter := 0
	seen := make(map[string]struct{}, len(b))
	for i := 0; i+k <= len(b); i++ {
		g := b[i : i+k]
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		if _, ok := setA[g]; ok {
			inter++
		}
	}
	union := len(setA) + len(seen) - inter
	if union == 0 {
		return false
	}
	return float64(inter)/float64(union) >= threshold
}
