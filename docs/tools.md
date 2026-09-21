# 工具与能力

当前整合分支注册下列十二个只读 MCP 工具。注册成功不等于完整候选已交付或新版已发布；缺失文件和验证边界见[交付状态](development/status.md)。`get_snapshot_info` 返回实际构建的能力和计数。工具不执行被审计项目。

| 工具 | 作用 |
|---|---|
| `get_snapshot_info` | 查询固定文件集合、能力和真实缓存/分析计数 |
| `list_snapshot_files` | 分页列出源码包中的文件和语言支持状态 |
| `query_security_facts` | 按类型、框架、角色和所属声明筛选事实 |
| `get_security_evidence` | 根据快照、文件和事实身份回取证据 |
| `read_snapshot_source` | 按固定文件哈希和字节范围读取源码 |
| `resolve_code_location` | 将导航位置转换为本快照中的调用点候选 |
| `query_entry_points` | 查询受支持的 Spring MVC 入口上下文 |
| `query_resource_operations` | 列出受限 Java/MyBatis 普通数据操作与未连接声明，不运行局部值流 |
| `inspect_operation_context` | 检查 Java 调用参数、局部/返回关系和 MyBatis 映射 |
| `inspect_entry_security` | 检查所选 Spring Security 配置的链与规则选择 |
| `trace_argument_origins` | 查询普通 Java 调用的指定实参来源，不要求 Mapper 或漏洞规则 |
| `trace_source_to_sink` | 从选定 MyBatis 文本替换参数自动回溯上游请求来源 |

## 按问题选择工具

源码已经足够时可以不调用工具。首次需要工具时核对固定快照和能力；同一会话可以复用核对结果。

**找结构。** 使用文件、事实、入口或资源清单。`handler_anchor` 指向方法声明，不是 `call_id`；通过入口的 `call_query` 查实际调用。资源清单返回的 `inspection.tool/arguments` 可用于继续检查选定操作。未连接声明不能因没有调用关系而丢弃。跟随 `page.next_cursor`，包括空页；保留每页覆盖信息，分页结束不证明运行时完整覆盖。

**查关系。** 先选定具体调用和问题。只需概览时使用 `summary`，查看指定实参时使用 `values` 与 `argument_index`；需要完整材料时使用 `full_request`。普通实参回溯见[接口说明](reference/argument-origins.md)。旧 `trace_source_to_sink` 仍要求根调用、Mapper、映射及搜索文件集合，不被新接口替换。

**回取证据。** 保留快照、分析/上下文身份、文件哈希和字节范围。使用证据或源码读取接口核对原文，不让模型重新抄写源码。源码引用真实不等于程序关系已验证；程序关系候选也不等于漏洞成立。离线导出器仍在待整合清单中，不属于这十二个 MCP 工具。

## 查询范围与实际成本

普通实参查询最多选择 16 个 Java 文件，每文件 256 KiB，合计 2 MiB，最多四跳调用者。资源清单最多选择 32 个 Java/XML 文件，其中 Java 最多 16 个、总计 2 MiB；这些是单次查询的限制，不是整仓覆盖承诺。

`summary`、`values`、`full` 是同一操作的输出视图，不是分析深度或独立裁决。首次请求仍计算完整操作；相同固定源码进程内的同一操作可以命中最后一条完整结果缓存。不同操作会替换缓存，跨进程不共享；查看 `operation_context` 中的 `computations`、`parse_attempts`、`cache_hits` 和 `cache_evictions`，不要仅按返回字节推算解析成本。

自动搜索的请求内缓存与上述单操作缓存不是同一个缓存。结构清单不默认调用深层局部值流。以上接口不安排下一次扫描，也不安装客户端或 Hooks。

## 结果不能混用

旧的直接来源投影与新的局部值流范围不同，不能互相投票。证据编号只属于对应上下文，不可跨上下文直接拼接。已知路径、常量分支和未知分支可以同时存在，必须一起保留。

零候选、不支持、解析失败、预算停止和关系被反证是不同结果。到达形参边界不证明攻击者可控；没有找到调用者不证明运行时没有调用。Spring 登录要求不能清除值依赖，MyBatis 参数化查询不能证明资源所有权检查存在。净化、业务规则与最终漏洞裁决留给宿主。详细语义见[参考索引](README.md)。
