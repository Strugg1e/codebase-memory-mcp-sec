# 普通 Java 实参来源查询

接口：`cbm.argument-origins.v1`；当前分支程序：`0.15.0-preview.1`。核心查询已进入整合分支，普通实参专项、回放及有限 Java 参考已独立编写；原始候选仍未恢复，见[交付状态](../development/status.md)。这不是已完成发布或完整验证声明。

本查询只处理程序关系，复用既有反向搜索、声明调用核对和局部值流。不依赖请求注解，不判断可信身份或最终漏洞。

## 输入

先用 `query_security_facts` 或 `resolve_code_location` 选择实际调用，不能使用方法声明编号。示例中的标识必须替换为当前固定快照的真实返回值：

```json
{
  "snapshot_id": "当前快照编号",
  "path": "Service.java",
  "analysis_id": "当前分析编号",
  "call_id": "选定调用编号",
  "argument_index": 0,
  "scope_paths": ["Service.java", "Caller.java"],
  "max_hops": 4,
  "max_paths": 16,
  "max_edge_checks": 128
}
```

argument_index 从零开始。不接受 mapper_path、mapping_path、rule_id 或 upstream_calls。根调用的被调用方法定义不必存在，因为本次调查的是接收的实参；每条跨方法上游关系仍须核对目标声明。

## 输出

| 字段 | 含义 |
|---|---|
| query_id | 绑定快照、构建、调用、参数、范围和预算，不是结果文件哈希 |
| selected_argument | 根实参的局部来源，不能代替跨方法结果 |
| paths | 从实参到范围内形参边界的候选关系 |
| source.kind | formal_parameter_boundary，不分类外部输入或可信身份 |
| boundary_reason | 没有候选调用者、目标未解析或深度限制等停止原因 |
| steps | 按 argument_to_origin 排列的调用现场、参数位置和局部关系 |
| contexts | 各调用对应的内部操作结果和局部证据表 |
| frontiers | 常量覆盖、未知来源、递归、预算和不支持写法的停止记录 |
| call_candidates | 逐项声明目标检查和未解析原因 |
| coverage / gaps / truncated | 实际范围、未知部分和预算状态 |

未解析的调用者保留当前边界，不虚构上游。已知路径、常量分支与未知分支可以并存。queue_exhausted 只说明本次队列结束，不证明应用分析完整。未处理状态不会在报告阶段触发新深度分析，local_relation 可为 null。

证据编号只属于对应 contexts[index].operation。内部操作结果没有 MCP 完整响应的 context_id；需要完整身份时，使用真实 anchor 显式调用 inspect_operation_context(view="full")，不能自行补造编号。现有[独立离线交接脚本](evidence-handoff.md)只接受显式取得的单操作完整结果，不导出本查询的全部结果；搜索范围、预算、frontiers 和未知项仍由宿主原样保留。该脚本不冒充原候选恢复。

## 关系与限制

沿用局部复制、覆盖、表达式、分支合并、受限同类辅助方法返回和 String 模型。对象引用来源不等于对象字段、数组或集合内容来源。

声明检查考虑类型、包、明确导入、唯一方法、参数数量和接收者重绑定，不是 Java 编译器的完整重载和类型解析。同类 this/隐式调用、接口、泛型、继承等仍可能无法连接。循环、完整异常/finally、堆内容、任意跨文件返回、隐式控制流和路径可满足性未新增支持。

最多 16 个 Java 文件，每文件 256 KiB，合计 2 MiB，四跳调用者；共享搜索上限为 128 次边检查、128 个状态、32 条形参边界路径，输出 4 MiB。路径上限不统计 frontier 数量，frontier 仍受状态、参数和输出上限约束。

运行时分派未验证；形参边界不证明攻击者可控，关系存在不证明调用一定发生，净化和授权不由本查询决定。query_id 相同也可能因预算或中断得到不同部分结果，应另存结果哈希及完成状态。

## 与旧规则及缓存的关系

trace_source_to_sink 保留原接口、源识别和 schema，共享搜索内核；旧规则仍从 MyBatis 文本替换处开始，在受支持的 Spring 标量输入处停止。普通查询不在请求注解处自动停止。

资源清单不自动执行本查询。搜索内部操作缓存只限本次请求，不是 inspect_operation_context 的最后一条完整结果缓存。get_snapshot_info.argument_origin_tracing 单独记录请求和解析尝试。

## 可运行的独立验证

```sh
python3 tests/security/test_argument_origins.py build/security/cbm-security-facts
python3 security/demo_arguments.py --mcp build/security/cbm-security-mcp
python3 tests/java-argument-reference/compare.py --mcp build/security/cbm-security-mcp
```

普通专项使用真实解析器和 MCP，覆盖普通形参、换位、复制与覆盖、分支、未知返回、目标类型、重载歧义、身份、文件和深度预算，以及错误请求后的继续使用。回放从真实事实清单取得调用编号，在四个无 Mapper、无请求注解的受控场景中检查结果及全部源码引用，不执行 Java。

[Java 参考说明](../../tests/java-argument-reference/README.md)单独编译运行仓库固定样例。四个场景各五次求值，只对有限输入观察进行核对；不能据此认定所有路径或漏洞结论。普通专项不会偷偷启动 Java 或安装依赖。

以上是独立开发的产品验收，不冒充原始候选的同名文件、历史专项或 Java 参考恢复。原候选取得后仍须逐文件比较；历史验证记录不能替代最终提交的新验证。查询结果并非单操作离线证据包，不能丢弃完整 trace 的范围、frontiers 和预算说明后只导出一段路径。
