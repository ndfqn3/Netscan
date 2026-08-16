# POC 模板编写指南

NetScan 支持通过 YAML / JSON 模板自定义漏洞检测（POC），无需重新编译程序。

## 快速开始

```yaml
id: redis-unauth-example
name: Redis 未授权访问
service: redis
severity: critical
request:
  proto: tcp
  payload: "INFO\r\n"
response:
  keywords:
    - "redis_version"
```

保存为 `my-poc.yaml`，然后：

```bash
./netscan pocs add ./my-poc.yaml
./netscan pocs list
./netscan pocs remove redis-unauth-example
```

## 模板字段说明

| 字段 | 必填 | 说明 |
|------|------|------|
| `id` | ✅ | 唯一标识，用于 add/remove |
| `name` | ❌ | 显示名称 |
| `service` | ❌ | 关联服务（用于 auto 匹配） |
| `port` | ❌ | 默认端口 |
| `severity` | ❌ | critical / high / medium / low |
| `request` | ✅ | 请求定义 |
| `response` | ❌ | 响应匹配规则 |
| `exploit` | ❌ | 关联的利用模块 id |

## request 字段

| 字段 | 说明 |
|------|------|
| `proto` | `http` / `tcp` / `udp`（默认 http） |
| `method` | HTTP 方法（GET/POST，默认 GET） |
| `path` | HTTP 路径 |
| `headers` | HTTP 请求头（键值对） |
| `body` | HTTP 请求体（POST） |
| `payload` | tcp/udp 原始载荷 |

## response 字段

| 字段 | 说明 |
|------|------|
| `status` | 期望的 HTTP 状态码列表 |
| `keywords` | 响应包含的关键字（任一命中即判定） |
| `regex` | 响应匹配的正则（任一命中） |
| `json` | JSON 键名（响应包含该键即命中） |

> 当 `response` 完全为空时，HTTP 状态码 200 即判定命中。

## 变量替换

请求中支持以下变量：

| 变量 | 说明 |
|------|------|
| `{{target}}` | 目标 IP/域名 |
| `{{port}}` | 目标端口 |
| `{{randstr}}` | 随机字符串 |
| `{{callback_host}}` | 回连地址 |
| `{{callback_port}}` | 回连端口 |

## 示例

### HTTP 检测（关键字匹配）

```yaml
id: actuator-exposure
name: Spring Actuator 未授权
service: http
severity: high
request:
  proto: http
  method: GET
  path: /actuator/env
response:
  keywords:
    - "java.version"
    - "systemEnvironment"
```

### TCP 检测（原始载荷）

```yaml
id: memcached-unauth
name: Memcached 未授权
service: memcached
severity: high
request:
  proto: tcp
  payload: "stats\r\n"
response:
  keywords:
    - "STAT"
```

### 正则匹配

```yaml
id: git-exposure
name: .git/config 泄露
service: http
severity: high
request:
  path: /.git/config
response:
  regex:
    - "\\[core\\]"
```

### JSON 键匹配

```yaml
id: es-info-leak
name: Elasticsearch 信息泄露
service: elasticsearch
severity: high
request:
  path: /_nodes
response:
  json:
    - "cluster_name"
```

## 内置 POC

内置 200+ POC（`netscan pocs list` 中 `builtin` 前缀），覆盖 Redis、MySQL、Tomcat、Docker、Nacos、Jenkins 等常见服务的高危未授权与 CVE 检测。
