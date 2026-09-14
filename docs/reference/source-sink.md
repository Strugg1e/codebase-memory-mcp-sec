# v0.14：从选定危险参数自动寻找输入来源

新增第十个只读 MCP 工具 `trace_source_to_sink`。
在固定文件集合中，从**选定的一次 Java Mapper 调用**反向搜索调用者，
复用已有调用目标校验、Java 局部值流和同类辅助方法返回摘要。
不再需要先人工填写 `upstream_calls`。

这是一条限定规则、语言和范围的自动路径查询，不是全仓库漏洞扫描。
Mapper、XML/注解格式和搜索文件集合仍由宿主或 Agent 明确选择。
工具不执行目标代码、OGNL、SQL、模型或来自目标的规则文件。

## 第一条内置规则

`spring-mybatis-text-substitution`，规则版本 `1`：

| 部分 | 实际模型 |
|---|---|
| 输入源 | Spring MVC 映射方法中，带明确请求输入绑定声明的标量形参 |
| 危险参数候选 | 选定 MyBatis XML 或有限注解中的 `${...}` 文本替换位置 |
| 传播 | 现有局部复制、覆盖、显式表达式依赖、分支合并、受限返回摘要与已校验声明调用候选 |
| 净化 | 未建模；不会因为函数名含 sanitize 或存在权限注解就清除依赖 |
| 结论 | 可能的源到参数依赖，不是 SQL 注入、授权或实际可执行路径证明 |

标量范围是基本类型和明确的 String/包装类型。已知同名类型冲突不按拼写猜测。
对象、数组、集合、请求 DTO 属性、Servlet getter 返回值和隐式请求绑定不在源模型内。
没有控制器标记的映射仍按现有入口规则保留为未确认注册的候选。
数值类型同样保留：数值绑定可能限制注入字符，不能仅因得到路径就报告 SQL 注入。

`#{...}` 不作为此规则的文本替换点；这不表示整个调用或其他风险安全。
XML 配置属性替换阶段、转义、动态片段与参数作用域仍保留 v0.12 的前提和缺口。
`${query.field}` 不把整个 query 的标量来源当成 field 的来源，不强行追踪。

规则目录随可信工具版本编译，通过 `--capabilities` 和 `get_snapshot_info` 查询。
本版只有一条内置规则，没有可加载任意规则的 DSL、通用外部库摘要或净化模型。

## 使用

先用 `query_security_facts` 或 `resolve_code_location` 取得根调用点编号：

```json
{
  "snapshot_id": "当前服务的固定快照编号",
  "path": "src/OrderService.java",
  "analysis_id": "该文件的分析编号",
  "call_id": "Mapper 调用点的事实编号",
  "mapper_path": "src/OrderMapper.java",
  "mapping_path": "resources/OrderMapper.xml",
  "scope_paths": [
    "src/OrderController.java",
    "src/OrderFacade.java",
    "src/OrderService.java"
  ],
  "rule_id": "spring-mybatis-text-substitution",
  "max_hops": 4,
  "max_paths": 16,
  "max_edge_checks": 128
}
```

`scope_paths` 必须包含根调用文件，只接受当前快照中的 Java 文件；它不是路径 glob。
同一文件出现两次会报错；文件顺序规范化，不改变结果身份。
所有文件应属于同一应用。工具不会自行判断应用分区，也不把所选范围当作全仓库。
注解模式设置 `mapping_format="annotation"`，保留 mapper_path，省略 mapping_path。

根调用与映射仍需明确选择。**自动的是调用者搜索和相关参数的反向组合**，
不是自动找全仓所有危险点、自动挑选映射、或从任意输入正向扫描全部操作。
没有 `upstream_calls` 参数；旧 `inspect_operation_context` 的显式路径模式继续保留。

## 如何计算

1. 在有界范围内解析 Java 文件，建立调用现场与所属方法目录。
2. 使用既有操作分析关联根 Mapper 和模板，分别记录每次文本替换。
3. 从对应实参取得局部来源集合，按每个可能形参分别继续调查。
4. 找到已识别映射方法的明确标量请求绑定时，输出输入源候选。
5. 否则按方法名寻找候选调用现场，再由原有校验器检查声明类型、包/导入、唯一目标、参数数量及重绑定等条件。
6. 只有校验接受的声明目标候选才进入下一层；参数换位按位置组合。
7. 保留所有受预算允许的分支、断点、未解析候选和源码证据。

按调用现场和参数保存状态，递归检查只作用于当前祖先路径，不使用全局方法名去重。
同一方法的两次调用不会交换实参；不同调用者不会被第一个成功结果吞掉。
继承、接口分派、复杂重载和解析器未支持的接收者仍可能无法连接。
目标校验并不等于已证明运行时动态分派，路径条件也未作可满足性求解。

## 返回结构

协议：`cbm.source-sink-paths.v1`。

| 字段 | 含义 |
|---|---|
| `trace_id` | 绑定快照、工具构建、规则、根调用、映射、范围及预算的查询身份，不绑定耗时 |
| `sinks` | 每个文本替换出现位置、参数索引或属性缺口、原模板条件 |
| `contexts` | 每次已计算的操作上下文保存一次，以 index 引用；包括原局部证据表 |
| `call_candidates` | 实际核对过的调用候选、接受或未解析原因、调用者与被调用者位置 |
| `paths` | 输入声明、逐步参数关系、证据索引、候选跳数、变换与未知项 |
| `states` | 搜索状态和父状态，关联具体调用、实参、模板位置及求解上下文 |
| `frontiers` | 没有继续展开的状态及原因：常量覆盖、未知值、无候选、循环或预算等 |
| `coverage` | 所选文件的哈希、分析情况，不是完整应用覆盖证明 |
| `gaps` / `file_analysis_gaps` | 通用缺口与文件/框架分析缺口 |
| `statistics` / `budgets` | 实际解析尝试、边校验、缓存命中、状态数量及本次上限 |

`paths[].steps_order="sink_to_source"`：步骤从根危险参数向请求来源排列。
每步的 local_relation 证据编号属于它引用的 contexts[index]，不要跨上下文混用。
`incoming_edge_index` 引用 call_candidates 中已接受的声明目标关系。
输入端保留参数类型、原声明和入口缺口；路径仅表示可能依赖。

`trace_id` 不等于一次执行结果文件的内容哈希。CPU预算或环境中断可能改变部分结果；
宿主需要另行记录结果哈希、完成状态和原始产物。

## 状态不可混用

- `candidate_paths_found`：至少找到一条输入依赖候选，仍需检查全部缺口和控制。
- `sink_mapping_unresolved`：根映射没有完成，不能当作没有危险点。
- `sink_analysis_incomplete`：模板分析不完整，不能根据空列表排除风险。
- `no_matching_sink_in_selected_mapping`：这个已分析映射没有本规则选中的替换点。
- `no_candidate_path_in_analyzed_subset`：未得到路径，不说明不存在漏洞。

`truncated` 与 `queue_exhausted` 分别表达预算和队列状态。队列为空仍可能有不支持项，
某条候选存在也不意味着其他分支已经完成。常量覆盖只终止该值的已知来源。
路径中的已知来源和未知分支可以同时存在。

输出始终保留 `security_verdict=not_evaluated`、`sanitizer_effects=not_modeled`。
已认证、permitAll、角色要求不能当作 SQL 净化；请求级规则可另外查询，不在此自动排除。

## 预算、缓存与资源

最多16个范围文件、合计2 MiB，每文件256 KiB；最多20,000条目录事实、1,024个调用现场。
最多4层调用者、128个边校验、128个搜索状态、32条路径，局部缓存正文合计2 MiB，输出4 MiB。
max_hops允许0，仅调查根方法；max_paths默认32；max_edge_checks默认128。
本次请求内复用操作上下文和边检查，结束后释放，不创建持久图或跨请求缓存。
现有目标校验可能再次解析源码；统计记录真实尝试，不声称每文件只解析一次。

10秒进程CPU检查在工作单元之间执行，不可抢占正在运行的同步分析。
宿主仍应设置独立进程的内存、墙钟时间和取消限制。超大返回会明确失败，不静默剪掉证据。

## 验证和可运行示例

```sh
make -f Makefile.security
make -f Makefile.security test
python3 tests/security/test_auto_trace.py build/security/cbm-security-facts
python3 security/demo_trace.py --mcp build/security/cbm-security-mcp
```

示例运行真实MCP和解析器，包含自动两跳、常量覆盖、已知来源与未知返回并存三个场景。
只选择根调用和范围，不传上游路径；源码全部是标记的测试样例，不执行Java目标。
测试还覆盖参数换位、调用现场隔离、类型冲突、错误导入、缺失映射、递归、上限、
固定身份、模板条件、精确引用及固定随机参数组合的独立来源模型对照。
代码中有测试不等于某个提交已通过，以该提交实际日志为准。
没有新增框架运行参考应用，也没有真实业务召回、准确率、模型费用或Harness接入结论。
