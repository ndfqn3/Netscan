# NetScan

一款用 Go 编写的全能网络扫描器，提供 **命令行（CLI）** 与 **图形界面（GUI）** 两种形态，集主机发现、端口扫描、服务识别、OS 识别、漏洞检测、Web 侦察于一体。

---

## 目录

- [功能概览](#功能概览)
- [快速开始](#快速开始)
- [编译与安装](#编译与安装)
- [命令行用法](#命令行用法)
- [图形界面用法](#图形界面用法)
- [项目结构](#项目结构)
- [平台支持与限制](#平台支持与限制)
- [移动端使用警告](#移动端使用警告)
- [免责声明](#免责声明)

---

## 功能概览

### 1. 主机发现与端口扫描

| 功能 | 说明 |
|------|------|
| 主机发现 | 同网段用 ARP（最可靠）、跨网段用 ICMP、无权限时回退 TCP |
| TCP Connect 扫描 | 全连接，跨平台可用 |
| TCP SYN 半开扫描 | 需 Linux + root |
| UDP 扫描 | 通过 ICMP 端口不可达报文判断 |
| FIN / NULL / Xmas / ACK | raw socket，需 Linux + root |
| 定时模板 | T0（偏执）~ T5（疯狂），自动推导超时与并发 |
| 速率限制 / 随机端口 | `--rate` / `--randomize` |

### 2. 指纹与识别

| 功能 | 说明 |
|------|------|
| 服务/版本识别 | 40+ 服务指纹 + 主动探针（SSH、FTP、HTTP、MySQL、Redis、MongoDB 等） |
| 操作系统识别 | 基于 TTL + 开放端口特征启发式判断 |
| CMS/Web 指纹 | 识别 WordPress、Discuz、ThinkPHP、DedeCMS、Joomla、Drupal、Laravel、Shiro、Spring Boot、Tomcat、Nginx、IIS 等 |

### 3. 漏洞检测（POC）

对常见高危服务发送轻量探测包（1-2 个包、2 秒超时），判定未授权访问风险：

Redis、MongoDB、Elasticsearch、Docker API、Jenkins、Nacos、Memcached、CouchDB、etcd、Consul、Hadoop YARN。

### 4. Web 侦察

| 功能 | 说明 |
|------|------|
| 目录/文件爆破 | dirsearch 式，内置 180+ 常见路径字典 |
| HTTP 安全头检查 | 检查 X-Frame-Options、CSP、HSTS 缺失与 Server 泄露 |
| 子域名爆破 | 内置 130+ 字典，支持 BFS 递归深度 + 反向 DNS |
| Whois / DNS 查询 | 域名注册信息 / A、CNAME、MX、NS、TXT 记录 |

### 5. 其他

| 功能 | 说明 |
|------|------|
| 路由跟踪 | `-tr`（traceroute） |
| Ping 测延迟 | `-sp` |
| Banner 抓取 | `--banner` |
| 多格式输出 | 普通文本、JSON、XML、grepable、CSV、**HTML 报告** |
| 代理扫描 | `--proxy socks5://` / `http://` |
| 定时扫描 + 变更监控 | `--monitor` / `--interval`，输出新增/消失项，退出码 10=有变化 |
| 快速命中即停 | `--stop-after-host` |
| 目标上限保护 | `--max-targets`，防误扫大网段导致内存爆炸 |
| proot 安全降级 | 移动端自动禁用 raw socket 并降并发 |

---

## 快速开始

直接下载 `dist/` 目录下对应平台的编译产物即可运行，无需任何依赖（GUI 除外，见下）。

```bash
# Windows 64 位
netscan-windows-x64.exe -target 192.168.1.1 -sT

# Linux 64 位
./netscan-linux-x64 -target 192.168.1.0/24 -p 80,443 -sV

# 查看版本
./netscan-windows-x64.exe -version
```

> GUI 版本（`netscan-gui-*`）依赖系统 WebView 运行时：Windows 需 WebView2（Win10/11 已预装），Linux 需 WebKitGTK，macOS 系统自带 WebKit。

---

## 编译与安装

### 前置条件

- Go 1.22+
- 仅编译 GUI 才需要 C++ 编译器与 WebView 运行时：
  - **Windows**：MSYS2/MinGW 的 g++，运行时需 WebView2
  - **Linux**：g++ + `libwebkit2gtk-4.0-dev`（`sudo apt install g++ libwebkit2gtk-4.0-dev`）
  - **macOS**：Xcode 命令行工具（自带 WebKit）

### 一键构建

产物输出到 `dist/`（与源码分离），CLI 交叉编译到 17 个平台/架构。

```powershell
# Windows：GUI + CLI（全部平台）
powershell -ExecutionPolicy Bypass -File build.ps1

# Windows：仅 CLI（全部平台）
powershell -ExecutionPolicy Bypass -File buildCLI.ps1
```

```bash
# Linux / macOS：GUI + CLI
chmod +x build.sh && ./build.sh

# 仅 CLI
chmod +x buildCLI.sh && ./buildCLI.sh
```

### 手动编译

```bash
go mod tidy

# CLI（纯 Go，可交叉编译到任意平台）
go build -o netscan ./cmd/cli

# GUI（基于 WebView，仅本机平台）
go build -ldflags "-H windowsgui" -o netscan-gui ./cmd/gui
```

### 运行测试

```bash
go test ./...
```

---

## 命令行用法

### 参数速查

**扫描相关**

| 参数 | 说明 |
|------|------|
| `-target` | 目标（必填）：IP / CIDR / 范围 / 域名，逗号分隔 |
| `-p` | 端口表达式（默认 `1-65535` 全端口） |
| `-sT` / `-sS` / `-sU` | TCP Connect / SYN / UDP 扫描 |
| `-sF` / `-sN` / `-sX` / `-sA` | FIN / NULL / Xmas / ACK 扫描 |
| `-T` | 定时模板 0-5（默认 3） |
| `-Pn` | 跳过主机发现 |
| `-sn` | 仅主机发现 |
| `-sV` | 服务与版本识别 |
| `-O` | 操作系统识别 |
| `--rate` | 每秒发包数限制（0=不限） |
| `--randomize` | 随机端口顺序 |
| `--exclude-ports` | 排除端口表达式 |
| `-v` | 详细输出（含关闭/过滤端口） |

**识别与检测**

| 参数 | 说明 |
|------|------|
| `--poc` | 高危端口未授权访问检测 |
| `--fp` | CMS/Web 指纹识别 |
| `--banner` | 抓取开放端口原始 banner |

**侦察工具**

| 参数 | 说明 |
|------|------|
| `-dir` | 目录爆破（dirsearch），端口用 `-p` 指定（默认 80） |
| `-sub` / `--sub-depth` | 子域名爆破 / 递归深度（1-3） |
| `-web` | HTTP 安全头检查 |
| `-whois` | Whois 查询 |
| `-dnsq` | DNS 记录查询 |
| `-https` | 使用 HTTPS（配合 `-dir`/`-web`） |
| `-tr` / `-tr-max` | 路由跟踪 / 最大跳数 |
| `-sp` | Ping 测延迟 |

**高级**

| 参数 | 说明 |
|------|------|
| `--proxy` | 代理：`socks5://127.0.0.1:1080` 或 `http://127.0.0.1:8080` |
| `--stop-after-host` | 命中首个存活主机/开放端口后立即停止 |
| `--max-targets` | 目标 IP 数量上限（默认 10000） |
| `--force-raw` | 强制使用 raw socket（覆盖 proot 降级） |
| `--monitor` / `--interval` | 定时扫描监控 / 间隔（如 `24h`） |
| `-sort` | 结果排序：`port` / `host` / `state` |
| `-oN/-oJ/-oX/-oG/-oC/-oH` | 输出：普通/JSON/XML/grepable/CSV/HTML 报告 |
| `-version` | 显示版本号 |

### 示例

```bash
# 快速扫描常见端口
./netscan -target 192.168.1.1 -sT -T4

# 服务识别 + 输出 JSON
./netscan -target 192.168.1.1 -p 80,443,22 -sV -oJ result.json

# 限速隐蔽扫描（每秒 50 包）
./netscan -target 192.168.1.0/24 -p 22,80,443 -sS --rate 50

# 高危检测 + CMS 指纹 + HTML 报告
./netscan -target 192.168.1.1 -sT --poc --fp -oH report.html

# 目录爆破 + Web 头检查
./netscan -target example.com -p 80 -dir -web

# 定时监控（有变化退出码 10）
./netscan --monitor example.com -target 192.168.1.0/24 -p 22,80,443 -sT
```

扫描结束后自动输出统计摘要（存活主机数、开放端口数、主机/服务分布）。

---

## 图形界面用法

双击 `netscan-gui-*` 启动，界面分左右两栏：

**左栏（配置）**

- **扫描目标**：目标、端口、定时模板
- **扫描技术**：TCP Connect / SYN / UDP / FIN / NULL / Xmas / ACK
- **扫描选项**：服务识别、版本识别、OS 识别、跳过主机发现、仅主机发现、反向 DNS、高危检测（POC）、CMS 指纹、Banner 抓取、命中即停
- **高级选项**：代理、速率限制、排除端口、结果排序
- **Web 侦察**：目录爆破、Web 头检查、子域名爆破（含深度）、Whois、DNS 记录、HTTPS

**右栏（结果）**

- **扫描结果**：实时表格展示，高危风险以红色 `⚠高危` 标记（悬停看详情）
- **操作按钮**：开始扫描 / 停止 / 导出 CSV / 导出 HTML 报告 / 路由跟踪 / Ping
- **Web 侦察结果**：侦察输出显示区

---

## 项目结构

```
portscanner/
├── cmd/
│   ├── cli/main.go              # CLI 入口（纯 Go，可交叉编译）
│   └── gui/main.go              # GUI 入口
├── internal/
│   ├── scanner/                 # 扫描引擎（核心，纯 Go）
│   │   ├── types.go             # 类型与常量
│   │   ├── targets.go           # 目标解析（IP/CIDR/范围/域名/IPv6）
│   │   ├── portdb.go            # 端口-服务数据库与端口表达式
│   │   ├── discovery.go         # 主机发现（ARP/ICMP/TCP）
│   │   ├── tcpscan.go           # TCP Connect 扫描 + banner
│   │   ├── rawscan_linux.go     # SYN/FIN/NULL/Xmas/ACK（raw socket）
│   │   ├── udpscan.go           # UDP 扫描
│   │   ├── service.go           # 服务/版本识别
│   │   ├── osdetect.go          # OS 识别
│   │   ├── fingerprint.go       # CMS/Web 指纹识别
│   │   ├── poc.go               # 高危未授权访问检测
│   │   ├── webscan.go           # 目录爆破 / 头检查 / 子域名爆破
│   │   ├── recon.go             # Whois / DNS 记录
│   │   ├── extras.go            # Ping / 路由跟踪 / Banner
│   │   ├── report.go            # HTML 报告生成
│   │   ├── monitor.go           # 定时扫描 + 变更监控
│   │   ├── proxy.go             # 代理连接
│   │   ├── proot.go             # proot 安全降级
│   │   ├── ratelimit.go         # 速率限制
│   │   ├── localnet.go          # 本机网段/ARP 判断
│   │   ├── scanner.go           # 扫描编排引擎
│   │   └── *_linux.go/*_windows.go/*_other.go   # 平台相关实现
│   └── webgui/                  # 图形界面
│       ├── app.go               # WebView 界面逻辑
│       └── index.html           # 界面（暗色主题 HTML/CSS/JS）
├── dist/                        # 编译产物（与源码分离）
├── build.ps1 / build.sh         # 全量构建（GUI + CLI）
├── buildCLI.ps1 / buildCLI.sh   # 仅构建 CLI
├── go.mod
├── README.md
└── RELEASE_NOTES.md
```

---

## 平台支持与限制

### 产物命名与架构

| 后缀 | 架构 | 适用系统 |
|------|------|---------|
| `-x64` | 64 位 x86（amd64） | 绝大多数现代 PC |
| `-x86` | 32 位 x86（386） | 老式 32 位系统 |
| `-arm64` | ARM 64 位（AArch64） | 树莓派 / Apple Silicon / 部分 Windows 设备 |

CLI 已交叉编译覆盖：Windows / Linux / macOS / FreeBSD / NetBSD / OpenBSD × x64 / x86 / arm64（macOS 无 x86）。

### 功能限制

- **TCP SYN / FIN / NULL / Xmas / ACK** 需要 Linux + root；Windows 等平台自动回退为 TCP Connect。
- **UDP 扫描**依赖 ICMP 报文监听，需管理员/root 权限。
- **代理扫描**仅对 TCP 连接与 HTTP 请求生效，raw socket 扫描不支持代理。
- **服务/版本识别**仅对 TCP 开放端口进行。

---

## 移动端使用警告

在 **Termux / proot** 等受限移动环境中：

- raw socket 通常不可用，大量并发会导致设备卡死或崩溃。
- 本工具会**自动检测** proot/Termux 环境并**安全降级**：禁用 raw socket、并发限制到 100 以下、发包速率限制到 500/s。
- 如需强制 raw socket，加 `--force-raw`（风险自负）。
- 建议移动端用 TCP Connect 扫描，并把端口范围缩小到 `top-1000` 或更小。

---

## 免责声明

本工具仅供网络管理员进行授权的安全评估与网络诊断使用。请勿在未获得授权的情况下对他人网络进行扫描，否则可能触犯法律。使用者须自行承担全部责任。
