# 完整操作结果的离线证据交接

`security/export_evidence.py` 是本轮独立实现的配套脚本，不是原始 `0.15.0-dev` 候选的恢复。它不是第十三个 MCP 工具，不改变现有十二个工具或分析语义。本版只在 POSIX 文件系统使用，实际验证平台以测试记录为准。

## 它核对什么

输入为已保存的 `inspect_operation_context(view="full")` 结果、实际调用参数、程序版本与构建身份，以及启动 MCP 时使用的原始快照。脚本只读取这些文件，不遍历目标目录，不调用解析器或模型，不联网，不执行被审计代码。

导出包保留完整输入的原始 UTF-8 字节，逐项回取并核对文件哈希、字节范围、UTF-8 边界及原文预览。每个引用保留自己在结果中的 JSON 路径；相同源码范围出现多次也不合并，局部证据编号不跨上下文重排。

| 核对层次 | 实际含义 |
|---|---|
| 原始快照与输入哈希 | 与宿主事先保存的准确字节相同，不接受换行或重新格式化后的另一份快照 |
| 操作身份 | 按当前身份格式复算分析编号和操作上下文编号，检查请求与结果一致 |
| 源码引用 | 每条字节范围及预览与指定快照中的源码相符 |
| 程序关系 | 不重新求解；原有关系、条件、未知项、证据表和截断状态原样保留 |
| 安全判断 | 不判断攻击者可控、权限有效、运行时可达或漏洞成立 |

`context_id` 标识操作上下文，不是结果内容哈希。同一上下文的已保存结果如果条件、未知项或截断状态不同，必须分别保存 `capture_sha256`，不能只用上下文编号替换旧结果。复核阶段沿用宿主原来记录的摘要，不从新的证据包中重新选择信任值。

身份哈希不是数字签名，不认证生成程序或贡献者。校验值必须来自可信任务记录；不能从待验包中读取一个哈希，再把它当作独立可信值。即使引用全部正确，原始关系判断仍可能错误。

## 保存真实完整结果

宿主记录实际请求、完整 `structuredContent` 和当前 `get_snapshot_info.product_capabilities` 的 `version/build_id`。不接受概览、聚焦视图、自动搜索内部 `contexts[].operation` 或自行补造的身份。

宿主可导入以下纯保存函数；下列变量来自真实 MCP 调用，不是需要填写的模拟结果：

```python
from pathlib import Path
import sys
sys.path.insert(0, "security")
from export_evidence import digest, make_capture, write_new

raw = make_capture(actual_arguments, full_structured_content,
                   snapshot_info["product_capabilities"])
write_new(Path("capture.json"), raw)
# 在可信任务记录中保存此摘要，不仅保存到将被交接的文件旁边。
capture_sha256 = digest(raw)
```

输入格式为 `cbm.operation-capture.v1`。它把调用参数、程序身份和结果一起绑定，不补充原文没有的条件、严重性或结论。`full` 表示没有做视图省略，不表示分析完整；`truncated=true` 和非空 `gaps` 仍然可以被交接。

自动实参搜索只能用真实 `anchor` 显式取得单操作完整结果再导出。本版不导出整条自动搜索结果；宿主必须另外保留搜索的 `scope_paths`、`coverage`、`frontiers`、预算与未知项，不能用一个操作包冒充整个查询。

## 导出和独立复核

`SNAPSHOT_SHA` 与 `CAPTURE_SHA` 是宿主可信记录中的值。两次执行可发生在不同进程；复核阶段不需要 MCP 程序，但需要可信的同一原始快照。

```sh
python3 security/export_evidence.py export \
  --snapshot snapshot.json --expect-snapshot "$SNAPSHOT_SHA" \
  --capture capture.json --expect-capture "$CAPTURE_SHA" \
  --output evidence.json

python3 security/export_evidence.py verify \
  --snapshot snapshot.json --expect-snapshot "$SNAPSHOT_SHA" \
  --bundle evidence.json --expect-capture "$CAPTURE_SHA"
```

成功只输出 `source_references_verified`；同时明确 `program_relations=not_reverified` 和 `security_verdict=not_evaluated`。复核器从可信快照重建引用清单，再与交接包逐项比较。引用丢失、增加、改写、上下文变更或校验值不符均失败。不会把空字段、`null`、未知枚举和未访问范围统一成安全结论。

源码范围使用 UTF-8 **字节**偏移，起止位置都必须位于字符边界。空范围也要检查：位于字符起点或文件末尾的空范围可以保留；位于中文字节或其他多字节字符中间的空范围必须拒绝。不能因空字节串能够解码就认定位置有效。

失败返回退出码 2，不在标准输出报告成功，不覆盖旧输出。输出先写到同目录的临时文件，再以不可覆盖方式发布，权限为 0600。输入只允许单硬链接普通文件，拒绝符号链接和 FIFO。输入路径、输出目录及其祖先目录须由可信宿主选择；脚本不从源码内容选择路径。

## 边界与数据最小化

快照沿用现有格式上限：1,024 个文件，单文件 1 MiB，源码合计 16 MiB，原始 JSON 32 MiB。保存输入最多 8 MiB；JSON 深度 96、节点 200,000；引用最多 8,192 项，展开源码合计 16 MiB，输出 JSON 最多 32 MiB。超限拒绝，不静默截断证据包。Java 操作仍遵守单文件 256 KiB 和最多四个显式上游调用的限制。

输出不包含整仓快照，只含完整保存输入和它引用的源码片段。完整结果及源码片段仍可能含秘密，不能因此自动公开。源码、注释和导出的文字始终是不可信数据；本脚本不负责整个宿主的提示注入防护。

## 可运行的受控示例

```sh
make -f Makefile.security
python3 security/demo_evidence.py --mcp build/security/cbm-security-mcp \
  --output-dir build/evidence-demo
python3 tests/security/test_evidence_bundle.py build/security/cbm-security-facts
```

示例目录必须不存在。示例使用仓库自带 Java 文本，调用真实 MCP 后先退出分析进程，再分别启动导出和复核进程。它同时检查已知参数依赖和未知返回分支，生成快照、保存输入、证据包和测试回执。没有调用模型或运行 Java，不是业务漏洞基准或 Token 成本对照。
