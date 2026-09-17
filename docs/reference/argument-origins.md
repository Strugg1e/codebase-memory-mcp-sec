# 普通 Java 实参来源查询

版本：`cbm.argument-origins.v1`，程序预览版 `0.15.0-preview.1`。

本查询只处理程序关系。它将既有反向搜索、声明调用核对和局部值流从 MyBatis 专用种子中解耦。
不是新污点规则，不依赖请求注解，不推断可信身份或最终安全结论。

## 输入

先通过 `query_security_facts` 或 `resolve_code_location` 选中实际方法调用，不能使用方法声明编号。
以下标识必须替换为当前快照的真实返回值：

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

不接受 `mapper_path`、`mapping_path`、`rule_id` 或 `upstream_calls`。目标调用的被调用方法定义不必存在：本次调查的是它接收的实参，不是它内部的行为。但每条跨方法上游关系仍须核对目标声明。

## 输出

| 字段 | 含义 |
|---|---|
| query_id | 绑定快照、构建、调用、参数、范围和预算；不是结果文件哈希 |
| selected_argument | 根调用实参的局部来源；不能用它替代跨方法结果 |
| paths | 从目标实参到可见范围形参边界的候选关系 |
| source.kind | formal_parameter_boundary，不分类外部输入或身份可信性 |
| boundary_reason | 为什么在该形参停止：没有候选调用者、目标未解析或深度限制 |
| steps | 按 argument_to_origin 排列的调用现场、参数位置与局部关系 |
| contexts | 每个调用现场对应完整操作结果及局部证据表 |
| frontiers | 覆盖为常量、未知来源、递归、预算和不支持写法的停止记录；附已取得步骤 |
| call_candidates | 逐项声明目标检查，区分已接受候选和未解析原因 |
| coverage / gaps / truncated | 文件处理范围、未知部分及预算状态 |

未解析的调用者会保留当前形参边界，而不是虚构上游路径。不能把该边界当成分析已覆盖全部上游。
同一次查询可以同时有已知路径、常量分支和未知分支。`queue_exhausted` 只表示本次工作队列结束，不能代表应用分析完整。
每个步骤的证据编号只属于所指向的 `contexts[index].operation`，不可跨上下文直接合并。
未处理的排队状态在报告阶段不会触发新的深度分析，相关 `local_relation` 可为 null。

内部 `contexts[].operation` 是求解器原始上下文，不具备 MCP 完整响应的 context_id，不能直接交给单操作导出器。
需要导出时，使用对应 anchor 调用 `inspect_operation_context(view="full")`，保留其真实快照和结果身份。
这是额外的显式查询，不宣称复用了搜索内部缓存，也不能自行补造编号。

## 关系与限制

沿用既有局部复制、覆盖、表达式与分支合并、受限同类辅助方法返回和 String 模型。
普通形参可以作为查询边界，包括对象引用；对象引用来源不等于字段、数组或集合内容来源。
沿用现有声明目标检查：类型、包、明确导入、唯一方法、参数数量、接收者重绑定。不是 Java 编译器的完整重载和类型解析；同类 this/隐式调用、接口、泛型、继承等仍可能无法连接。

循环、完整异常/finally、堆内容、任意跨文件返回、隐式控制流和路径可满足性未新增支持。
运行时分派始终未验证；参数可传播不证明该调用一定发生。净化和授权不由此查询决定。

输入范围最多 16 个 Java 文件，每文件 256 KiB，合计 2 MiB；调用者最多四跳。
共享搜索限制为 128 次边检查、128 个状态、32 条形参边界路径；输出仍限 4 MiB。
路径上限不统计 frontier 数量，frontier 受状态、参数与最终输出大小约束。
重复语义查询的 query_id 一致，但执行预算或环境中断可能改变部分结果，应另存结果哈希和完成状态。

## 与旧规则及缓存的关系

`trace_source_to_sink` 保留原接口、源识别和结果 schema。它与新查询共同调用同一个搜索内核；旧规则继续从 MyBatis 文本替换位置播种并在支持的 Spring 标量输入处停止。
普通查询不在请求注解处自动停止。资源操作清单不触发此查询；Agent 选择具体实参后才调用。
搜索内部的操作缓存只限本次请求，不是 `inspect_operation_context` 的最后一条结果缓存。
`get_snapshot_info.argument_origin_tracing` 单独记录请求和解析尝试，避免与旧规则混算。

## 验证

```sh
make
python3 tests/security/test_argument_origins.py build/security/cbm-security-facts
python3 security/demo_arguments.py --mcp build/security/cbm-security-mcp
```

专项测试使用真实解析器和 MCP，覆盖普通形参、换位、覆盖、类型冲突、歧义和停止原因。
独立 Java 参考见[运行说明](../../tests/java-argument-reference/README.md)，只编译执行仓库自带的小型样例，不构建被审计项目。
语义依据：Java 语言规范 15.7.4 与 15.12；编译期声明与运行时方法选择不能混同。
参考：https://docs.oracle.com/javase/specs/jls/se25/html/jls-15.html
