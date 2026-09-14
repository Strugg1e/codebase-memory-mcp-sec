# 工具与能力

本分支提供下列十个只读 MCP 工具。`get_snapshot_info` 返回当前构建的能力信息；表中名称与 `security/mcp.c` 保持一致，由文档检查验证。生产工具不执行目标代码。

| 工具 | 作用 |
|---|---|
| `get_snapshot_info` | 查询固定文件集合、能力和真实缓存/分析计数 |
| `list_snapshot_files` | 分页列出源码包中的文件和语言支持状态 |
| `query_security_facts` | 按类型、框架、角色和所属声明筛选事实 |
| `get_security_evidence` | 根据快照、文件和事实身份回取证据 |
| `read_snapshot_source` | 按固定文件哈希和字节范围读取源码 |
| `resolve_code_location` | 将导航位置转换为本快照中的调用点候选 |
| `query_entry_points` | 查询受支持的 Spring MVC 入口上下文 |
| `inspect_operation_context` | 检查 Java 调用参数、局部/返回关系和 MyBatis 映射 |
| `inspect_entry_security` | 检查所选 Spring Security 配置的链与规则选择 |
| `trace_source_to_sink` | 从选定 MyBatis 文本替换参数自动回溯上游请求来源 |

## 使用顺序

侦查先查询能力与入口；验证先明确命题和目标操作。导航结果需要转换为当前快照的具体调用现场，再读取概览。按需展开参数关系、原始源码、安全配置或回溯路径。

`handler_anchor` 指向方法证据，不是 `call_id`。使用入口返回的 `call_query` 寻找实际调用。`trace_source_to_sink` 不要求手工填写上游路径，但仍需要选择根调用、Mapper、映射和搜索文件集合。

## 结果不能混用

`summary`、`values`、`full` 是操作上下文的视图，不是不同投票者。旧的直接来源投影与新的局部值流分析范围不同。不同上下文中的证据编号不可直接合并；始终保存快照、上下文身份和原始引用。

净化效果、对象授权和业务要求尚未由工具通用判定。Spring 的登录要求不能清除数据依赖，MyBatis 参数化查询也不能证明资源所有权检查存在。详细语义见[参考索引](README.md)。
