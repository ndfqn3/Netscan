# Release Notes

## v5.0.3

> 内置 POC 模板库统一放在 WEB 页：搜索 + 使用当前目标/端口/OAST 一键运行。

### 🖥 GUI

- WEB 页「内置 POC 模板库」：按 ID/名称搜索（默认前 300 条）、显示等级，点「运行」直接使用 Web POC 卡片的目标/端口/OAST 执行
- 修复此前 GUI 资源页「POC 模板」只列自定义 POC、无法查看/使用内置模板的问题（内置库仅放 WEB 页，资源页保持仅管理自定义 POC）
- 后端新增 `pocBuiltinList` 绑定与 `POCBuiltinList` 门面导出（5,380 条，含新增 64 条）
- 补充 `BuiltinPOCList` 单测：数量与过滤均验证通过

## v5.0.2

> GUI 内置 POC 模板库（5,380 条）可浏览、可搜索、可一键运行。

### 🖥 GUI

- WEB 页新增「内置 POC 模板库」：按 ID/名称搜索（默认显示前 300 条）、显示等级，点击「运行」直接使用 Web POC 卡片的目标/端口/OAST 配置执行
- 解决 GUI 资源页「POC 模板」只显示用户自定义 POC、无法查看/使用 v5.0 新增内置模板的问题
- 后端新增 `pocBuiltinList` 绑定与 `POCBuiltinList` 门面导出（含官方增量 64 条，共 5,380 条）

## v5.0.1

> 静态安全审计整改 + GUI 反馈增强（vulhub 5 靶场实测：POC 检测 + 利用链）。

### 🔒 安全审计修复（24 项）

- **P1**：目标范围/CIDR 上界回绕与 `uint32` 溢出（`255.255.255.255/32` 等）、IPv6 终点 panic；插件 Webhook 空请求 panic；GUI 并发扫描结果串扰（拒绝并发）；无效代理不再静默直连（fail-closed）；拿 shell 链逐步校验状态，不再无条件报告成功
- **P2**：JSON extractor 改用 `encoding/json` 逐层遍历；UDP ICMP 仅 Code 3 端口不可达且校验内嵌目标 IP/UDP；DNS 查询带 ctx 超时；Store/Monitor 错误传播（迁移失败关闭 DB、原子写状态文件）；`rand_int` 溢出与随机串长度上限；OAST 事件 TTL/容量上限、Serve 失败复位；公共回调 nil 防护；`parsePortSpec` 越界范围拒绝；BSD 桩显式返回 `ErrUnsupported`；`NETSCAN_TLS_VERIFY=1` 可显式开启证书校验
- **回归测试**：目标范围/CIDR 回绕、端口边界、JSON 路径、rand 极端值、wappalyzergo 技术栈识别、既有全部单测

### 🖥 GUI 反馈（对齐 CLI）

- 扫描页新增实时「扫描日志」：端口扫描结束后自动执行 POC 全量检测，逐端口输出命中详情（ID/名称/等级/复现 URL）与汇总
- POC 命中行自动标注 `⚠ CVE-...` 标签，结束状态显示命中端口数
- 「扫描目标漏洞」卡片改为本页独立输出框（原输出写入隐藏面板，点击后无反馈）
- Web POC 卡片迁至「Web 侦察」页；Banner/侦察/插件输出镜像到扫描日志

## v5.0

> 模板库重构：用真实 nuclei 模板替换机械生成的漏洞库，只收录 MIT 许可来源。

### 🔐 指纹引擎合规替换（无 nmap 授权）

- **移除一切 nmap 归属内容**：端口-服务名表改为依据 IANA 服务名注册表与通用约定整理；SMB build 对照表依据 MS-NLMP 规范与微软公开资料整理；nmap XML 导入仅为**文件格式兼容**（解析用户自有输出），不含 nmap 代码或数据
- **新增 wappalyzergo（MIT）**：Web 技术栈识别（响应头/HTML，数据源 webappanalyzer/wappalyzer），与自研 CMS 规则合并输出 `--fp`
- **新增 nerva（Apache-2.0，与 MIT 兼容）**：170+ 协议服务指纹引擎，作为自研正则探针的兜底识别（`pkg/portscan/nerva.go`）
- fingerprintx（Apache-2.0）已归档，采用其维护分支 nerva；版权与许可证详见 `THIRD_PARTY_NOTICES.md` 第 7 节

### 🔄 变更

- **移除机械生成的漏洞库**：删除 `moduledb_gen.go` / `pocdb_gen.go`（约 1000 个模块共用少量关键词、OR 匹配导致大量误报）
- **新增 nuclei 模板引擎**：支持 `status / word / regex / size / dsl 子集` 匹配器与 `matchers-condition`
- **模板来源（仅 MIT）**：`projectdiscovery/nuclei-templates` 3,580 个 + AllForOne 清单中 MIT 许可仓库去重新增 871 个 = **4,451 个模板（5,856 条路径条目）**；完整版权与许可证见 `THIRD_PARTY_NOTICES.md`
- **采集/转换工具链**：`tools/nuclei-pipeline/`（collect → convert → select → emit），结果可复现
- **质量门槛**：剔除畸形路径模板与近全命中的大 OR 探测器；按模板 id 大小写不敏感去重（官方优先）
- **软 404 基线**：随机路径基线统一用于 POC 与漏洞库，排除“任意路径返回同一页面”的误报
- **Active 模块误报修复**：`docker-unauth` / `es-file-read` / `nacos-register` / `tomcat-manager` 增加基线判断与更严格特征
- **并发模型修复（防 OOM）**：扫描主机/端口、主机发现、目录爆破、子域名爆破、漏洞扫描统一改为“先拿并发令牌再创建协程”（`internal/netx/pool.go` 的 `ForEachBounded`），消除“先为每个任务 go、再在协程内等信号量”导致全端口/大网段扫描瞬时创建千万级协程的问题；新增协程上限回归测试
- **软 404 基线强化**：基线改为记录任意状态码（403 / 自定义 404）的随机路径响应，并用对称的 `BaselineKey`（剔除 URL 编码回显 token 与请求路径）比对；修复 Jenkins 全 403、Apache 404 错误页等场景下 `--scan-vuln` / `--poc-scan` 的大量误报（实测 Jenkins 46→1、17→2，Apache 10→0，保留 robots.txt 与 Jenkins 面板等真阳性）
- **软 404 基线再强化（vulhub 实测驱动）**：`BaselineKey` 追加剔除请求路径（含去前导斜杠/去查询串/query 各参数值）、请求体与 UA、长随机串（CSRF/session）与数字（时间戳/耗时），比较时以 16 字符 shingle 的 Jaccard 相似度（≥0.95）兜底；vulhub 333 靶场实测把「兜底错误页」误报清零：CraftCMS 503 页 49→0、PHP 49→0、Drupal 24→1、Gitea 166→3、Grafana 83→2，同时保留真实命中（httpd CVE-2021-41773 仍检出）
- **GUI 全功能集成**：新增「🧰 工具」页——结果多格式导出（HTML/JSON/CSV/Grepable/XML/Normal）、资产对比与定时自动重扫、插件市场地址设置、POC/模块/字典/Shell链管理器；POC 扫描支持 `--poc-id` 定向过滤与 `--oast` 回调；SSH 支持已知凭据直连弹命令行；漏洞利用页可列出全部模块；扫描选项补齐随机端口顺序/强制 raw/详细输出/目标数量上限
- **新增 `--poc-id` 定向过滤**：`--poc-scan --poc-id CVE-xxxx-xxxx` 仅运行 id/name 匹配的模板，用于靶场/单漏洞定向验证
- **POC 引擎 v2（多请求/raw + OAST 回调）**：`internal/poc/poctemplate.go` 支持多 HTTP 请求序列、`raw` 原始请求、模板静态变量替换与 `redirects` 标记（nuclei 语义，默认不跟随重定向）；新增内置 HTTP 回调（`--oast <ip:port>`，`{{interactsh-url}}` 注入 + `oast` 匹配器），可检出 SSRF/RCE 外带类模板（DNS/LDAP 协议暂不支持）；MIT 模板收录量 **4,451 → 5,316**（官方 4,344 + AllForOne-MIT 972，含 177 条回调类），并新增弱词/黑名单质量门槛（实测误报模板剔除）
- **模板质量门槛补充**：剔除实测误报的弱模板（如仅凭 `Content-Range`+206 判定 Nginx 溢出的 CVE-2017-7529 简化版）
- **包结构重构（领域分层）**：`internal/scanner` 58 个文件按领域拆分为 `pkg/portscan`（扫描核心，不依赖利用库/SQLite）、`internal/{netx,webscan,poc,exploit,store,plugin,report}`；`internal/scanner` 保留为兼容门面（CLI/GUI 零改动），外部模块可单独引用 `pkg/portscan`
- **内嵌 ffuf 模糊测试（MIT，全功能）**：以源码 `third_party/ffuf` + `go.mod replace` 方式集成 ffuf v2.1.0（`internal/ffufrun` 适配层，复用其完整引擎：多词表/多关键字、clusterbomb/pitchfork/sniper、Encoder、raw/原始请求文件、延时/限速/超时、匹配过滤(状态码/大小/词数/行数/正则/耗时、and/or)、自动校准(策略/自定义串/按主机)、递归目录、HTTP2/SNI/客户端证书/重放代理、Scraper、审计/调试日志、json/ejson/html/md/csv/ecsv 导出，输出重定向为流式回调）；CLI 新增 `--fuzz-*` 全量开关；GUI 新增「🎯 模糊测试」独立标签页（模式/字典/匹配过滤/高级选项/实时输出/停止）
- **子域名/虚拟主机爆破（ffuf）**：`--fuzz-mode subdomain --fuzz-sub <域名>`（生成 `http(s)://FUZZ.<域名>[:端口]`，泛解析自动校准）与 `--fuzz-mode vhost --fuzz-vhost <域名> --fuzz-url http://IP:PORT/`（注入 `Host: FUZZ.<域名>` 虚拟主机发现），CLI 与 GUI 均可用；版权与依赖许可证见 `THIRD_PARTY_NOTICES.md` 第 5 节
- **内置 PayloadsAllTheThings 字典（MIT，逐文件许可审计）**：66 个 .txt 字典（39,057 行，去重后）收录于 `internal/payloads/pat/`，`--fuzz-w builtin:<名称>` 直接调用（如 `builtin:springboot_actuator`、`builtin:param_miner_lowercase_headers`），GUI「工具→字典」可查看；已对模拟 Actuator 服务实测命中；逐文件审计排除了 1 个 GPL 文件，详见 `THIRD_PARTY_NOTICES.md` 第 6 节
- **来源审计结论（未入库）**：trickest/cve 与 tki8769-v/cve_poc_exp_in_github（均 MIT）为 CVE→PoC 链接索引/采集管线（175k+ markdown、JSONL 状态），不含可执行 nuclei 模板，按"可转换+质检通过"标准不入 POC 库
- **POC 引擎 v3（参考 nuclei 语义）**：新增 payloads + attack(clusterbomb/pitchfork/batteringram)、模板变量与 helper 运行时求值(rand_int/rand_text_*/rand_base/to_lower/to_upper/md5/sha1/sha256/base64)、matcher 内 `{{...}}` 与请求同值渲染、索引 DSL(`status_code_2`/`body_3`/`header_2`/`content_type`/`location`/`response`/`duration`/`interactsh_protocol`,`to_lower()` 包裹)、`negative` 匹配器、`oast_request`(回调请求内容匹配)、raw 请求自动补 `Content-Length`（nuclei 行为）；转换器同步升级（多 http 块上限 6、`@timeout/@Host` 注解剥离、payloads/动态变量放行）。据此从官方 MIT 库补齐 **50 个此前无法转换的 CVE 模板**（log4j/spring4shell/Confluence/WebLogic/Jenkins 等，`internal/poc/nuclei_pocs_extra_gen.go`），库规模 5,316 → **5,366**；CVE-2016-3088 已对 vulhub 实测命中，两台良性服务全量扫描 **0 误报**
- **文档修正**：README 删除“近千个漏洞模块”等失实表述

### ✅ 冒烟验证（本地良性测试页）

- `--poc-scan`：误报 55 → 0，仅保留真阳性命中（ambassador 诊断页）
- `--scan-vuln`：误报 3 → 0
- 单 IP 全 65,535 端口黑洞地址扫描：33.7s 完成，峰值工作集 84MB（旧实现会先堆积 6.5 万个协程栈；/24 网段可达 1,660 万个）

---

## v4.1.0（当前版本）

> 平台化完善版本：插件系统五类全落地、爆破协议完善、通配符过滤、HTTPS 支持、远程插件市场、大量 bug 修复。

### ✨ 新增功能

| 功能 | 使用方式 | 说明 |
|------|---------|------|
| 插件系统五类 | `plugin` 子命令 | poc/exploit/report/output/notification 全落地，声明式 YAML/JSON |
| report 插件 | 插件 `type: report` | Go template 渲染扫描报告文件 |
| output 插件 | 插件 `type: output` | Go template 自定义输出格式 |
| notification 插件 | 插件 `type: notification` | 扫描完成后推送结果到 webhook |
| 远程插件市场 | `--plugin-market <url>` | 从远程拉取插件列表与插件文件 |
| 通配符 DNS 过滤 | `--sub` 自动 | 随机子域名探测 + /24 网段过滤，消除通配符误报 |
| HTTPS 指纹/探测 | 自动识别 `https`/`https-alt` | 8443 等 HTTPS 端口指纹识别 |
| Ping TCP 回退 | `--sp` | 无 ICMP 权限时自动回退 TCP 探测 |
| Whois referral 跟随 | `--whois` | 跟随 IANA referral 查询具体注册局 |
| 全类型反弹 shell | `--shell` | 12 种：bash/sh/nc/ncat/python/python2/lua/node/php/perl/ruby/powershell |

### 🐛 修复

- **MySQL/PostgreSQL 爆破修复**：PostgreSQL 协议解析 3 处 bug（payload 切片、消息偏移、md5 十六进制），爆破恢复可用
- **一键拿 shell RCE 链修复**：内置 RCE 链 Port 参数缺失 + Path 占位符不替换，导致 RCE 链完全失效
- **误报大幅下降**：后台检测 404 误报（43→4）、redis-write-shell 非 Redis 误报、xss-reflect 泛化匹配
- **FIN/NULL/Xmas 扫描状态**：开放端口正确返回 `open|filtered`
- **崩溃/竞态/泄漏**：用户自定义 regex panic、BruteSSHOnce 竞态、raw/udp pending map 泄漏、爆破 goroutine 爆炸等 45+ 项
- **乱码/死代码**：POC 名称 mojibake、defaultUsers/totalProbes 死代码清理

### 🔧 构建

- 新增 `buildgui.ps1` / `buildcli.ps1` / `buildgui.sh` / `buildcli.sh` 四个分平台构建脚本

---

## v4.0

> 指纹与漏洞库增强版本：nmap 级 OS 精确识别、近千漏洞模块、爆破协议完善。

### ✨ 新增功能

| 功能 | 说明 |
|------|------|
| nmap 级 OS 精确识别 | TTL + 端口特征 + SMB/NTLM build 指纹 + SSH/HTTP banner，识别到具体 Windows 版本 |
| 近千漏洞模块 | `moduledb_gen.go` / `pocdb_gen.go` 生成 1000+ 检测/利用模块 + 300+ POC 模板 |
| nmap top 端口指纹库 | `topPorts` 100 端口 + `commonPorts` 282 服务映射 |
| 全量漏洞报告 | `--vuln-report` 输出所有可检测漏洞的名称 + 复现步骤 |
| 爆破协议完善 | 7 协议（ftp/ssh/telnet/redis/smtp/mysql/postgresql），worker pool 并发 + 服务分类字典 |
| Web 安全头检查 | `--web` 检查 X-Frame-Options 等安全头 |

---

## v3.0

> 平台化版本：模块/POC/字典/拿 shell 链热插拔 + 插件系统初版 + 一键拿 shell。

### ✨ 新增功能

| 功能 | 说明 |
|------|------|
| 平台化模块系统 | `module list/add/remove`，YAML/JSON 热插拔漏洞检测/利用模块 |
| 平台化 POC | `pocs list/add/remove`，YAML/JSON POC 模板 + 变量替换引擎 |
| 平台化拿 shell 链 | `shell list/add/remove`，数据驱动的多步利用链（占位符替换） |
| 字典管理 | `dict list/add`，服务分类用户名字典 + Top1000 密码 |
| 插件系统初版 | `plugin list/install/remove`，声明式插件（poc/exploit/report/output/notification） |
| 一键拿 shell | `--get-shell`，Redis cron / Docker 逃逸 / Jenkins RCE / CouchDB RCE / RCE 链自动选择 |
| 弱口令爆破 | `--brute`，7 种协议 + 自定义字典 |
| 漏洞利用 | `--exploit auto/<模块>`，主动利用 + 自动匹配 |
| 资产库 | `--store` / `--history` / `--diff`，SQLite 持久化 + 变更对比 |

---

## v2.0

> 全能扫描器版本：新增高危未授权检测、CMS 指纹、代理、HTML 报告、子域名深度爆破、定时监控等 10 项能力，CLI 与 GUI 功能对齐。

### ✨ 新增功能

| 功能 | 使用方式 | 说明 |
|------|---------|------|
| 高危未授权访问检测 | `--poc` | Redis、MongoDB、ES、Docker、Jenkins、Nacos 等，结果标 `[高危]` |
| CMS/Web 指纹识别 | `--fp` | WordPress、Discuz、ThinkPHP、DedeCMS、Shiro 等 + 版本提取 |
| 代理扫描 | `--proxy` | 支持 `socks5://` 与 `http://`，TCP 连接与 HTTP 请求走代理 |
| HTML 报告 | `-oH report.html` | 自包含暗色主题报告，内嵌 CSS |
| 子域名深度爆破 | `--sub-depth 1-3` | BFS + 反向 DNS 递归，队列实现 |
| 定时扫描 + 变更监控 | `--monitor` / `--interval` | 对比上次结果输出差异，退出码 10/0/1 |
| 快速命中即停 | `--stop-after-host` | 首个存活主机/开放端口即停 |
| proot 安全降级 | 自动 / `--force-raw` | 移动端自动禁 raw socket、降并发 |
| 目标上限保护 | `--max-targets` | 解析阶段提前校验，防误扫大网段卡死 |
| 版本号自动注入 | `-version` | 构建时从 `git describe` 注入 |

### 🔧 GUI 更新

- 新增「高级选项」卡片（代理 / 速率 / 排除端口 / 排序）
- 新增「Banner 抓取」「命中即停」开关
- 新增「导出 HTML 报告」「路由跟踪」「Ping」按钮
- 高危风险红色 `⚠高危` 标记（悬停显示详情）
- Web 侦察新增「子域名爆破深度」

### 📝 文档

- README 重构（功能分类、参数表格、快速开始、目录结构、平台矩阵）
- 新增「移动端使用警告」章节

---

## v1.x

- 核心扫描能力：主机发现（ARP/ICMP/TCP）、多技术端口扫描、服务/版本识别、OS 识别
- 输出格式：JSON / XML / grepable / 普通文本
- Web 侦察：目录爆破、子域名爆破、Whois、DNS、Web 头检查
- 路由跟踪、Ping、Banner 抓取、统计摘要
- 中文图形界面（WebView 渲染）

---

## 升级指南

- **向后兼容**：所有旧参数保持不变，新参数均为可选，不影响已有脚本。
- **状态文件**：监控状态保存在 `~/.netscan_state/`，清理可删除该目录。
- **proot 用户**：移动端会自动降级，如需 raw socket 改用 `--force-raw`。
- **GUI 依赖**：Windows 需 WebView2，Linux 需 WebKitGTK，macOS 系统自带。

## 全局约束

- 核心纯 Go（CLI 无 CGO），单文件 exe，跨平台。
- 所有网络操作均有超时控制。
- 保持命令行参数向后兼容。
