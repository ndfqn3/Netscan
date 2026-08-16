# Release Notes

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
