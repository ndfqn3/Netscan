# Release Notes

## v2.0（当前版本）

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

## 历史版本

### v1.x

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
