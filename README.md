# NetScan 网络扫描器

一个使用 Go 编写的网络端口扫描器，提供**命令行（CLI）**与**图形界面（GUI）**两种形态，支持主机发现、多技术端口扫描、服务/版本识别与操作系统识别。

## 功能特性

- **主机发现**：同网段用 ARP（最可靠）、跨网段用 ICMP、无权限时回退 TCP，综合判断主机存活；支持「仅主机发现」模式（`-sn`）。
- **端口扫描**：
  - TCP Connect（全连接，跨平台可用）
  - TCP SYN（半开扫描，需 Linux + root）
  - UDP 扫描（通过 ICMP 端口不可达报文判断）
  - FIN / NULL / Xmas / ACK 扫描（raw socket，需 Linux + root）
- **服务与版本识别**：内置 40+ 服务指纹正则与主动探针，覆盖 SSH、FTP、SMTP、POP3、IMAP、HTTP（nginx/Apache/IIS/Tomcat 等）、MySQL、PostgreSQL、Redis、Memcached、MongoDB、Elasticsearch、RabbitMQ、MQTT、VNC、RDP 等常见服务。
- **操作系统识别**：基于 TTL 与开放端口特征（RDP/SMB/SSH/NFS 等）启发式判断。
- **灵活的目标语法**：单 IP、CIDR、IP 范围、域名、IPv6 字面量，支持逗号分隔与组合。
- **灵活的端口表达式**：单端口、端口段、枚举、`top-N` 常用端口、全部端口，支持**排除端口**（`--exclude-ports`）。
- **定时模板**：T0（偏执）到 T5（疯狂）六档，自动推导超时与并发数。
- **速率限制**（`--rate`，对标 masscan）与**随机端口顺序**（`--randomize`）。
- **多格式输出**：普通文本、JSON、XML、grepable、CSV、**HTML 报告**（`-oN` / `-oJ` / `-oX` / `-oG` / `-oC` / `-oH`）。
- **实时流式输出**：扫描结果逐条实时打印，无需等待扫描全部完成。
- **中文图形界面**（WebView 渲染，现代暗色主题，跨平台）。
- **Web 侦察**：目录/文件爆破（dirsearch）、HTTP 安全头检查、子域名爆破（支持递归深度）、Whois 查询、DNS 记录查询。
- **高危未授权访问检测**（`--poc`）：对 Redis、MongoDB、Elasticsearch、Docker、Jenkins、Nacos、Memcached、CouchDB、etcd、Consul、Hadoop 等常见高危服务发送轻量探测，标记 `[高危]`。
- **CMS/Web 指纹识别**（`--fp`）：识别 WordPress、Discuz、ThinkPHP、DedeCMS、Joomla、Drupal、Laravel、Shiro、Spring Boot、Tomcat、Nginx 等。
- **代理扫描**（`--proxy socks5://...` 或 `http://...`）：TCP 连接与 HTTP 请求走代理（raw socket 不支持代理）。
- **定时扫描 + 变更监控**（`--monitor`、`--interval`）：与上次结果比对，输出新增/消失项，退出码 10=有变化、0=无变化。
- **快速命中即停**（`--stop-after-host`）、**目标上限保护**（`--max-targets`，防误扫 `/0` 导致内存爆炸）、**proot 安全降级**（移动端自动禁用 raw socket 并降并发）。

## 技术栈

- 语言：Go 1.22+
- GUI：WebView（`github.com/webview/webview_go`，HTML/CSS/JS 渲染）
- 依赖：`golang.org/x/net`（ICMP）、`golang.org/x/sync`、`golang.org/x/sys`

## 目录结构

```
portscanner/
├── cmd/
│   ├── cli/                     # 命令行入口(纯 Go, 可交叉编译)
│   │   └── main.go
│   └── gui/                     # 图形界面入口
│       └── main.go
├── internal/
│   ├── scanner/                 # 扫描引擎(核心)
│   │   ├── types.go             # 类型与常量定义
│   │   ├── targets.go           # 目标解析(IP/CIDR/范围/域名/IPv6)
│   │   ├── portdb.go            # 端口-服务数据库与端口表达式解析
│   │   ├── discovery.go         # 主机发现
│   │   ├── tcpscan.go           # TCP Connect 扫描
│   │   ├── rawscan_linux.go     # SYN/FIN/NULL/Xmas/ACK(raw socket)
│   │   ├── rawscan_other.go     # 非 Linux 平台回退
│   │   ├── udpscan.go           # UDP 扫描
│   │   ├── service.go           # 服务/版本识别
│   │   ├── osdetect.go          # 操作系统识别
│   │   ├── ratelimit.go         # 速率限制
│   │   ├── localnet.go          # 本机网段/ARP 判断
│   │   ├── arp_*.go             # ARP 探测(Windows SendARP)
│   │   ├── scanner.go           # 扫描编排引擎
│   │   └── refused_*.go         # 跨平台"连接被拒绝"判断
│   └── webgui/
│       ├── app.go               # WebView 界面逻辑
│       └── index.html           # 界面(暗色主题 HTML/CSS/JS)
├── dist/                        # 编译产物(与源码分离)
├── build.ps1                    # Windows 构建脚本
├── build.sh                     # Linux/macOS 构建脚本
├── go.mod
└── README.md
```

## 编译与运行

### 前置条件

- Go 1.22 或更高版本
- GUI 编译需要 C++ 编译器与 WebView 运行时：
  - **Windows**：MSYS2/MinGW 的 g++，运行时需 **WebView2**（Win10/11 已预装，否则需安装 Microsoft Edge WebView2）
  - **Linux**：g++ + `libwebkit2gtk-4.0-dev`（Debian/Ubuntu 可用 `sudo apt install g++ libwebkit2gtk-4.0-dev`）
  - **macOS**：Xcode 命令行工具（系统自带 WebKit）

### 一键构建（产物输出到 `dist/`，与源码分离）

Windows（PowerShell）：

```powershell
powershell -ExecutionPolicy Bypass -File build.ps1
```

Linux / macOS：

```bash
chmod +x build.sh && ./build.sh
```

脚本会交叉编译 CLI 到 Windows / Linux / macOS / FreeBSD / NetBSD / OpenBSD，并在**当前平台**编译 GUI。

### 产物命名与架构对照

| 文件名后缀 | 架构 | 适用系统 |
|-----------|------|---------|
| `-x64`    | 64 位 x86（amd64/x86_64） | 绝大多数现代 PC |
| `-x86`    | 32 位 x86（386/i686） | 老式 32 位系统 |
| `-arm64`  | ARM 64 位 | 树莓派 / Apple Silicon / 部分 Windows 设备 |

Windows 用户根据系统位数选择：

- 64 位系统（绝大多数）：`netscan-windows-x64.exe`、`netscan-gui-windows-x64.exe`
- 32 位系统：`netscan-windows-x86.exe`

### 手动编译

```bash
go mod tidy

# CLI(纯 Go, 任意平台)
go build -o netscan ./cmd/cli

# GUI(基于 WebView, 需 C++ 编译器, 仅本机平台)
go build -ldflags "-H windowsgui" -o netscan-gui ./cmd/gui
```

### 测试

```bash
go test ./...
```

## 命令行用法

```bash
netscan -target 192.168.1.0/24 -p 1-1000 -sT -T4 -sV

# 常用参数
-target string    目标(必填): IP/CIDR/范围/域名, 逗号分隔
-p string         端口表达式(默认 1-65535 全端口)
-sT                TCP Connect 扫描
-sS                TCP SYN 半开扫描(需 root)
-sU                UDP 扫描
-sF / -sN / -sX / -sA   FIN / NULL / Xmas / ACK 扫描
-T int            定时模板 0-5(默认 3)
-Pn               跳过主机发现
-sn               仅主机发现
-sV               服务与版本识别
-O                操作系统识别
--rate int        每秒发包数限制(0=不限)
--randomize       随机端口顺序
--exclude-ports   排除端口表达式
-v                详细输出
-sort string      结果排序: port / host / state
--banner          抓取开放端口原始 banner
-sp               仅 ping 测延迟(不扫端口)
-tr               路由跟踪(traceroute)
-tr-max int       路由跟踪最大跳数(默认 30)
--poc             高危端口未授权访问检测
--fp              CMS/Web 指纹识别
--proxy string    代理: socks5://127.0.0.1:1080 或 http://127.0.0.1:8080
--stop-after-host 命中首个存活主机/开放端口后立即停止
--max-targets int 目标 IP 数量上限(默认 10000)
--force-raw       强制使用 raw socket(覆盖 proot 安全降级)
--monitor string  定时扫描监控(与上次结果比对)
--interval string 监控间隔(如 24h), 留空只执行一次
-oN/-oJ/-oX/-oG/-oC/-oH  输出(普通/JSON/XML/grepable/CSV/HTML 报告)
-version          显示版本号

Web 侦察参数：

-dir               目录/文件爆破(dirsearch), 端口用 -p 指定(默认 80)
-sub               子域名爆破
-sub-depth int     子域名爆破递归深度(1-3, 默认 1)
-whois             Whois 查询
-dnsq              DNS 记录查询
-web               HTTP 安全头检查
-https             使用 HTTPS(配合 -dir/-web)

扫描结束后自动输出统计摘要(存活主机数、开放端口数、主机/服务分布)。

示例：

```bash
# 快速扫描常见端口
./netscan -target 192.168.1.1 -sT -T4

# 服务识别 + 输出 JSON
./netscan -target 192.168.1.1 -p 80,443,22 -sV -oJ result.json

# 限速隐蔽扫描(每秒 50 包)
./netscan -target 192.168.1.0/24 -p 22,80,443 -sS --rate 50

# 仅发现存活主机
./netscan -target 192.168.1.0/24 -sn

# 路由跟踪
./netscan -target 192.168.1.1 -tr

# ping 测延迟
./netscan -target 192.168.1.1 -sp

# 抓取开放端口 banner
./netscan -target 192.168.1.1 -p 80,443 -sT --banner

# 扫描并导出 CSV
./netscan -target 192.168.1.1 -sT -sV -oC result.csv

# 目录爆破(dirsearch)
./netscan -target 192.168.1.1 -p 80 -dir

# HTTP 安全头检查
./netscan -target example.com -web

# 子域名爆破
./netscan -target example.com -sub

# Whois 查询
./netscan -target example.com -whois

# DNS 记录查询
./netscan -target example.com -dnsq
```

## 图形界面用法

1. 在「目标」输入框填入扫描目标（IP / CIDR / 范围 / 域名，多个用逗号分隔）。
2. 在「端口」输入框填入端口表达式（`80`、`1-1000`、`80,443,8080`、`top-1000`、`-`）。
3. 选择定时模板（T0 到 T5）。
4. 勾选扫描技术（TCP Connect / TCP SYN / UDP / FIN / NULL / Xmas / ACK）。
5. 勾选扫描选项（服务识别、版本识别、操作系统识别、跳过主机发现、仅主机发现、反向 DNS）。
6. 勾选「Web 侦察」选项（目录爆破、Web头检查、子域名爆破、Whois、DNS记录、HTTPS），结果会显示在下方「Web 侦察结果」区域。
7. 点击「开始扫描」，结果实时显示，可随时「停止」或「导出结果」（CSV）。

## 平台限制说明

- **TCP SYN / FIN / NULL / Xmas / ACK** 等基于 raw socket 的扫描技术需要 Linux 系统并以 root 权限运行；在 Windows 等平台会自动回退为 TCP Connect 扫描。
- **UDP 扫描**依赖 ICMP 报文监听，通常需要管理员/root 权限。
- 服务识别与版本识别仅对 TCP 开放端口进行。

## 移动端使用警告（Termux / proot）

- 在 Termux / proot 等受限移动环境下，raw socket 通常不可用，大量并发会导致设备卡死或崩溃。
- 本工具会**自动检测** proot/Termux 环境并**安全降级**：禁用 raw socket 扫描技术、把并发数限制到 100 以下、把发包速率限制到 500/s。
- 如需强制使用 raw socket，可加 `--force-raw`（风险自负）。
- 建议在移动端使用 TCP Connect 扫描，并把端口范围缩小到 `top-1000` 或更小，避免设备过载。

## 免责声明

本工具仅供网络管理员进行授权的安全评估与网络诊断使用。请勿在未获得授权的情况下对他人网络进行扫描。
