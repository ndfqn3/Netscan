# Third-Party Notices

NetScan 本体以 MIT 许可证发布（见 `LICENSE`）。本文档列出内置 Web POC（`internal/poc/nuclei_pocs_gen.go`）
所收录的第三方 nuclei 模板来源、版权与许可证，以及采集/转换工具链的出处；同时列出以源码内嵌方式
引入的第三方组件（`third_party/`，如 ffuf 模糊测试引擎）的版权与许可证。

生成快照：2026-10-01（2026-10-04 增补 ffuf 一节）。生成方式与复现步骤见 `tools/nuclei-pipeline/README.md`。

---

## 1. projectdiscovery/nuclei-templates

- 来源：<https://github.com/projectdiscovery/nuclei-templates>
- 采集 commit：`8b9d065ccb04`（由 `tools/nuclei-pipeline/collect.py` 记录的 `collect_manifest.json` 固定）
- 许可证：MIT License，Copyright (c) 2025 ProjectDiscovery, Inc.
- 收录情况：4,408 个模板（含 2026-10-05 引擎 v3 增量收录 64 个，见 internal/poc/nuclei_pocs_extra_gen.go）

## 2. AllForOne 模板清单与采集脚本

- 来源：<https://github.com/AggressiveUser/AllForOne>
- 许可证：MIT License，Copyright (c) 2023 AggressiveUser
- 使用方式：`tools/nuclei-pipeline/collect.py` 参考其采集脚本实现，并固定使用其
  `PleaseUpdateMe.txt`（commit `a2d9358f656726d75b76fa804db41e5028b60cfb`，157 个仓库）。
  脚本与许可证副本见 `tools/nuclei-pipeline/`。

## 3. 经 MIT 许可并被收录模板的仓库

以下仓库来自 AllForOne 清单，许可证经 LICENSE 文件识别为 MIT，且其模板在按 `id`
与官方模板去重后仍有新增内容进入生成代码：

| 仓库 | 采集 commit | 版权声明 | 新增模板 |
|------|-------------|----------|----------|
| [PedroF-369/nuclei_templates](https://github.com/PedroF-369/nuclei_templates) | `7399a62723d0` | Copyright (c) 2021 Geeknik Labs | 747 |
| [mosesrenegade/nuclei-templates](https://github.com/mosesrenegade/nuclei-templates) | `1a41da068741` | Copyright (c) 2020 ProjectDiscovery, Inc. | 35 |
| [damon-sec/Nuclei-templates-Collection](https://github.com/damon-sec/Nuclei-templates-Collection) | `8c1dd2ad0f13` | Copyright (c) 2021 Geeknik Labs | 29 |
| [kh4sh3i/nuclei-templates](https://github.com/kh4sh3i/nuclei-templates) | `a6d7b30a492d` | Copyright (c) 2020 ProjectDiscovery, Inc. | 29 |
| [pikpikcu/nuclei-templates](https://github.com/pikpikcu/nuclei-templates) | `cbf9fd29b2ce` | Copyright (c) 2020 Exposed Atoms. | 16 |
| [geeknik/the-nuclei-templates](https://github.com/geeknik/the-nuclei-templates) | `36a6d14bce32` | Copyright (c) 2025 Brian Carpenter, Deep Fork Cyber, geeknik | 6 |
| [th3r4id/nuclei-templates](https://github.com/th3r4id/nuclei-templates) | `81a05c3417de` | Copyright (c) 2020 ProjectDiscovery, Inc. | 5 |
| [smaranchand/nuclei-templates](https://github.com/smaranchand/nuclei-templates) | `4ee444967714` | Copyright (c) 2020 ProjectDiscovery, Inc. | 4 |

AllForOne 清单中另有 10 个 MIT 仓库被一并采集转换，但其模板与官方来源重复、或无法被
NetScan 的单请求匹配子集表达，因此没有新增内容进入生成代码。

## 4. 未收录来源说明

AllForOne 清单共 157 个仓库：121 个采集成功、36 个已删除或不可访问。按“仅 MIT 来源”的项目要求，
以下来源的模板**仅采集到本地工作目录，不进入生成代码与发行物**：

- 97 个未声明任何许可证的仓库（含 `praetorian-inc/chariot-launch-nuclei-templates`，23 个模板；
  以及 `ExpLangcn/NucleiTP`、`ARPSyndicate/kenzer-templates` 等大型社区集合）
- 3 个 GPL、2 个 Apache-2.0、1 个 Unlicense 仓库

因此，本文档未包含上述仓库的模板内容或版权声明。

## 5. 源码内嵌组件：ffuf（Web 模糊测试引擎）

- 来源：<https://github.com/ffuf/ffuf>（快照 v2.1.0）
- 内嵌路径：`third_party/ffuf/`（module `github.com/ffuf/ffuf/v2`，经 `go.mod` `replace` 本地引用，
  编译进 CLI `--fuzz-*` 与 GUI「Web 模糊测试(ffuf)」功能）
- 许可证：MIT License，Copyright (c) 2021 Joona Hoikkala
- 许可证全文见 `third_party/ffuf/LICENSE`（条款与本文件第 8 节相同，仅版权行不同）

其传递依赖（`vendor/` 内，均保留各自 LICENSE）：`github.com/PuerkitoBio/goquery`（BSD-3-Clause）、
`github.com/adrg/xdg`（MIT）、`github.com/andybalholm/brotli`（MIT）、`github.com/ffuf/pencode`（MIT）、
`github.com/pelletier/go-toml/v2`（MIT）、`golang.org/x/{net,sys,crypto,term}`（BSD-3-Clause）。

## 6. PayloadsAllTheThings（内置字典资源）

- 来源：<https://github.com/swisskyrepo/PayloadsAllTheThings>（commit `3ac27901c711bdf3f5b65a7b1d1820a1f65bd09a`）
- 许可证：MIT License，Copyright (c) 2019 Swissky（全文见 `internal/payloads/pat/LICENSE`）
- 使用方式：66 个 .txt 字典逐文件许可审计后收录于 `internal/payloads/pat/`（保留原分类目录结构），
  通过 `builtin:<名称>` 供 ffuf 模糊测试使用（GUI「工具→字典」可查看全部名称；清单见 `internal/payloads/pat/SOURCE.json`）
- 处理说明：逐文件扫描全部文本（175k+ 文件的三库审计），行级去重 42,196 → 39,057 行；3 个 CC/BSD 命中
  （`MachineKeys.txt`、`jsonp_endpoint.txt`、`Python.md`）经人工核实为误报（十六进制串/URL 子串/正文引用），
  1 个真实 GPL 源文件 `Upload Insecure Files/Picture Compression/createBulletproofJPG.py` 已排除、未收录。
- 质检：内置 `springboot_actuator` 字典已对真实（模拟）Spring Boot Actuator 服务完成命中验证。

## 7. 指纹引擎：wappalyzergo 与 nerva

本项目不含任何 nmap 源码、nmap-service-probes 或 nmap-services 数据。nmap 结果 XML 的导入功能仅为
文件格式兼容（解析用户自有的 nmap 输出文件），不复制 nmap 代码或数据；端口-服务名表依据 IANA 服务名
注册表与业界通用约定整理，SMB build 对照表依据 MS-NLMP 协议规范与微软公开资料整理。

### wappalyzergo（Web 技术栈指纹，MIT）
- 来源：<https://github.com/projectdiscovery/wappalyzergo>（v0.3.4）
- 许可证：MIT License，Copyright (c) 2023 ProjectDiscovery, Inc.（全文见第 8 节）
- 指纹数据源：<https://github.com/enthec/webappanalyzer>、<https://github.com/HTTPArchive/wappalyzer>（均 MIT）
- 使用方式：`internal/webscan/wapp.go` 识别响应头/HTML 技术栈，与自研 CMS 规则合并输出
- 许可证全文见 `vendor/github.com/projectdiscovery/wappalyzergo/LICENSE`

### nerva（服务指纹引擎，Apache-2.0，与 MIT 兼容）
- 来源：<https://github.com/praetorian-inc/nerva>（v1.70.3）
- 许可证：Apache License 2.0（全文见 `vendor/github.com/praetorian-inc/nerva/LICENSE`）
- 说明：nerva 是 praetorian-inc/fingerprintx（Apache-2.0，已归档）的维护分支；本项目采用 nerva 作为
  服务指纹引擎（`pkg/portscan/nerva.go`，作为自研正则探针的兜底识别），未直接依赖已归档的 fingerprintx
- 兼容性：Apache-2.0 为宽松许可证、与 MIT 兼容；本项目整体以 MIT 发布，包含 nerva 时保留其版权、
  许可证与声明，不修改其源码

## 8. MIT License 全文

第 1 节来源的许可证全文（第 2、3 节各来源适用相同条款，仅版权行不同）：

```
MIT License

Copyright (c) 2025 ProjectDiscovery, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

上述条款同样适用于第 2、3 节来源，其版权行分别为：

- Copyright (c) 2023 AggressiveUser（AllForOne 清单与采集脚本）
- Copyright (c) 2021 Geeknik Labs（PedroF-369/nuclei_templates、damon-sec/Nuclei-templates-Collection）
- Copyright (c) 2020 ProjectDiscovery, Inc.（mosesrenegade、kh4sh3i、th3r4id、smaranchand）
- Copyright (c) 2020 Exposed Atoms.（pikpikcu/nuclei-templates）
- Copyright (c) 2025 Brian Carpenter, Deep Fork Cyber, geeknik（geeknik/the-nuclei-templates）

## 9. 免责声明

内置模板仅用于授权范围内的安全测试与自查。使用者应自行确保对目标系统的测试已获得合法授权。
