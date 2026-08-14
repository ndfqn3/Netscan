# Release Notes — NetScan v2.0

## 变更列表

### 新增功能

1. **高危端口未授权访问检测（POC）**：新增 `--poc`，对 Redis、MongoDB、Elasticsearch、Docker API、Jenkins、Nacos、Memcached、CouchDB、etcd、Consul、Hadoop YARN 等常见高危服务发送轻量探测包（1-2 个包、2 秒超时），判定未授权访问风险，结果标记 `[高危]`。
2. **CMS/Web 指纹识别**：新增 `--fp`，识别 WordPress、Discuz、ThinkPHP、DedeCMS、Joomla、Drupal、Laravel、Shiro、Spring Boot、Tomcat、Nginx、IIS 等，支持版本号提取（被动指纹 + 响应特征）。
3. **代理扫描**：新增 `--proxy socks5://host:port` 或 `--proxy http://host:port`，所有 TCP 连接与 HTTP 请求走代理（基于 `golang.org/x/net/proxy`，纯 Go）。
4. **HTML 报告生成**：新增 `-oH report.html`，生成自包含暗色主题 HTML 报告（含目标、统计、主机/端口/服务/风险明细），内嵌 CSS，无需外部依赖。
5. **子域名深度爆破**：`SubdomainBrute` 升级为广度优先搜索（BFS），新增 `--sub-depth 1-3`，通过反向 DNS 递归发现新域名，队列 + 循环实现（无递归函数）。
6. **定时扫描 + 变更监控**：新增 `--monitor target` 与 `--interval 24h`，扫描结果保存到 `~/.netscan_state/`，与上次比对输出 `+ 新增`/`- 消失`，生成差异文件，退出码 10=有变化、0=无变化、1=错误（文件锁防止同一目标并发执行）。
7. **快速命中即停**：新增 `--stop-after-host`，命中首个存活主机或首个开放端口后立即优雅停止。
8. **proot 安全降级**：自动检测 Termux/proot 环境，禁用 raw socket 并降低并发/限速，新增 `--force-raw` 覆盖。
9. **目标上限保护**：新增 `--max-targets`（默认 10000），在目标解析阶段提前校验，防止误输入 `/0` 导致内存爆炸（16M 主机直接报错而非卡死）。
10. **版本号自动注入**：`version` 由构建脚本通过 `git describe --tags --always --dirty` 注入（`-ldflags "-X main.version=..."`），新增 `-version` 参数。

### GUI 同步更新

- 新增「高危检测(POC)」「CMS指纹」开关。
- 结果表中高危风险以红色 `⚠高危` 标记（悬停显示详情）。

## 升级指南

- **命令行向后兼容**：所有旧参数保持不变，新增参数均为可选，不影响已有脚本。
- **状态文件位置**：监控状态保存在 `~/.netscan_state/`，如需清理可删除该目录。
- **proot 用户**：升级后移动端扫描会自动降级，如之前依赖 raw socket 请改用 TCP Connect 或加 `--force-raw`。

## 全局约束

- 纯 Go 核心（CLI 无 CGO），保持单文件 exe、跨平台（Windows/Linux/macOS）。
- 所有网络操作均有超时控制。
- GUI（WebView）为独立二进制，依赖系统 WebView 运行时。
