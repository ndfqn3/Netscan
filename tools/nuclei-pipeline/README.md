# nuclei-pipeline

把 GitHub 上的 nuclei HTTP 模板转换成 NetScan 内置 POC（`internal/poc/nuclei_pocs_gen.go`）的工具链。

## 来源与许可

- `projectdiscovery/nuclei-templates`（MIT，Copyright (c) ProjectDiscovery, Inc.）——主来源。
- `AggressiveUser/AllForOne`（MIT，Copyright (c) 2023 AggressiveUser）——采集其维护的公开模板仓库列表。
  `PleaseUpdateMe.txt` 固定自 commit `a2d9358f656726d75b76fa804db41e5028b60cfb`（2023-09-05，157 个仓库）；
  许可证副本见 `AllForOne-LICENSE.txt`。
- **只收录 MIT 许可来源**：AllForOne 清单中有大量仓库未声明许可证（97 个）或为 GPL/AGPL/Unlicense/Apache，
  `select.py` 会将其全部过滤。其中 Praetorian 的 `praetorian-inc/chariot-launch-nuclei-templates`
  无任何许可证声明，因此仅采集、不收录进生成代码。
- 完整版权与许可证列表见仓库根目录 `THIRD_PARTY_NOTICES.md`。

## 依赖

- Python 3.9+，`PyYAML`
- `git` 在 PATH 中（或设置环境变量 `GIT` 指向 git 可执行文件）

## 用法

```bash
python collect.py   # 浅克隆清单仓库 -> work/pool/，检测许可证 -> work/collect_manifest.json
python convert.py   # 转成 NetScan 可执行的模板子集 -> work/converted.jsonl
python select.py    # MIT 过滤 + 按 id 去重 + 质量门槛 -> work/selected.jsonl
python emit.py      # 生成 ../../internal/poc/nuclei_pocs_gen.go
```

`collect.py` 支持断点续跑：`work/pool` 中已存在的仓库会跳过；网络中断后重跑即可。
设置 `NUCLEI_WORK` 可自定义工作目录（默认 `<脚本目录>/work`）。

## 收录规则

- 收录 **多请求/raw HTTP 模板**（≤3 个 http 块、≤6 个请求）与
  `status / word / regex / size / dsl 子集` 匹配器；支持模板静态变量替换与
  `redirects` 标记（与 `internal/poc/poctemplate.go` 的求值器保持一致）。
- 运行时占位符白名单：`BaseURL/RootURL/Hostname/Host/Port/Scheme/randstr/target/port/callback_host/callback_port/interactsh-url`；
  `interactsh_protocol` 匹配器转换为 `oast` 类型（内置 HTTP 回调，扫描时用 `--oast <ip:port>` 启用）。
- 按模板 `id`（大小写不敏感）去重，官方 `nuclei-templates` 优先。
- 质量门槛：
  - 路径含空白/控制字符（畸形请求，会误命中错误页回显）→ 剔除；
  - `matchers-condition: or` 且匹配器超过 20 个（近乎全命中的探测器）→ 剔除；
  - 仅 `status` 匹配器的 AllForOne 新增模板 → 剔除；
  - 池模板中仅靠 `PHP Version / PHP Extension / phpinfo` 等通用字样匹配 → 剔除；
  - 实测误报模板黑名单（`select.py` 的 `DENY_IDS`）→ 剔除。
- 快照结果（2026-10-03）：官方 4,344 + AllForOne-MIT 972 = **5,316 个模板**（含 177 条回调类）写入生成文件。

## 结果复现说明

- 官方来源使用采集到的 `projectdiscovery/nuclei-templates` 克隆（HEAD 记录在 `work/collect_manifest.json`）。
- 每次重新生成 `internal/poc/nuclei_pocs_gen.go` 后请执行：
  `gofmt -w internal/poc/nuclei_pocs_gen.go && go build ./... && go vet ./... && go test ./...`
