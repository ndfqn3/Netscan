# 插件开发指南

NetScan 采用**声明式插件**（JSON / YAML），纯 Go 实现、跨平台、轻量，无需 Wasm/动态库。

## 插件类型

| 类型 | 说明 |
|------|------|
| `poc` | 自定义漏洞检测（复用 POC 模板引擎） |
| `exploit` | 自定义漏洞利用（复用 POC 模板） |
| `report` | 自定义报告格式（预留） |
| `output` | 自定义输出格式（预留） |
| `notification` | 自定义通知（webhook） |

## 插件格式

插件文件放在 `./plugins/` 目录（或 `plugins/` 相对当前目录）。

### POC 插件示例

```yaml
id: my-custom-poc
type: poc
name: 自定义 Redis 检测
version: 1.0.0
service: redis
severity: high
request:
  proto: tcp
  payload: "INFO\r\n"
response:
  keywords:
    - "redis_version"
```

### 通知插件示例

```yaml
id: my-webhook
type: notification
name: 企业微信通知
version: 1.0.0
webhook: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx"
```

## 插件管理命令

```bash
./netscan plugin list              # 列出已加载插件
./netscan plugin install p.yaml    # 安装插件(本地文件)
./netscan plugin remove my-poc     # 卸载插件
./netscan plugin update            # 同步插件(当前本地模式)
```

## 目录结构

```
plugins/
├── my-poc.yaml          # POC 插件
├── my-webhook.yaml      # 通知插件
└── ...
```

## 注意事项

- 插件采用声明式配置，无沙箱隔离，请仅加载可信来源的插件。
- 插件市场（GitHub 仓库）目前为本地模式；如需远程市场，可自行实现 `plugin install <name>` 的远程拉取逻辑。
- 关于 Wasm / Go Plugin（.so）：Go 的 `.so` 插件仅限 Linux + CGO，与「跨平台 + 轻量」目标冲突；Wasm 需要引入 Wasm 运行时（约 2-5MB）。因此本版本采用声明式插件作为主方案，保证 Windows/Linux/macOS/BSD 全平台一致。
