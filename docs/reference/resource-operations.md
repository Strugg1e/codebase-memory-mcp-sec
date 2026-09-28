# 资源清单、缓存与证据交接

本页对应现有十二个 MCP 工具，不增加分析范围。以下专项按产品验收独立编写，不是原始 `0.15.0-dev` 测试或归档恢复。完整交付状态见[版本记录](../development/status.md)。

## 列清单与查关系是两个操作

`query_resource_operations` 枚举选定应用范围中的普通 MyBatis 操作。参数化、常量以及新增、修改、删除操作均可出现，不要求先选择漏洞规则。`application_id` 是宿主指定的应用边界，不是工具独立发现的业务身份。

清单只做结构提取和受支持的映射核对；`statistics.local_flow_evaluations` 与 `statistics.return_summary_evaluations` 为零。它不会写入或替换完整操作缓存，也没有完整操作的 `context_id` 或局部值流证据表。

需要具体关系时，使用返回的 `operation.inspection.tool` 与 `operation.inspection.arguments`；需要完整结果时，使用概览返回的 `full_request`。不要自行猜调用编号或把结构对象补上身份后当成完整结果。

## 分页、身份与未解决项

| 情况 | 消费端应如何处理 |
|---|---|
| 本页没有操作但 `page.next_cursor` 非空 | 继续请求后续页；不能按空数组提前结束 |
| 候选被拒绝或无法连接 | 保留 `attempts` 中的位置、状态和原因，不只保存成功操作 |
| 同一查询改变页大小或每页检查次数 | 查询身份保持一致；游标表示下一项任务，不是第几个成功操作 |
| 改变应用、文件范围、映射模式或操作过滤器 | 重新查询，不复用旧游标；另一个快照的游标也不兼容 |
| 调整文件列表顺序 | 同一固定快照内按路径规范化，不改变结果；重新序列化快照仍会改变快照身份 |
| `enumeration_complete=true` | 只表示限定任务枚举结束；仍须检查文件缺口、未解决项与目录截断，不表示应用安全 |

`declarations` 是独立声明清单，不随操作类型过滤而消失。其 `nominated_calls_in_scope` 只是待核对的提名，不是已证明的调用关系。逐页保存时可按源码引用识别重复声明，但不能把两个不同调用现场合成一个操作。

XML 与注解同时存在时，保留各自候选，不替运行时决定优先级。SQL 操作类型无法识别时，即使请求了具体类型，也保留带有 `operation_kind_unresolved` 的候选，不能静默过滤掉未知项。

`operation_id` 用于限定范围内的具体操作。`resource_candidate.peer_group_id` 只表示同一宿主应用、Mapper 和精确表名拼写的比较候选，不能替代操作编号，不能证明数据库身份、资源归属或相同授权要求。

## 完整操作缓存

缓存仅保存固定源码进程中的最后一条完整操作结果，容量为一。首次请求 summary 仍执行完整操作分析；后续 summary、values、full 视图可以复用该结果。按参数聚焦 values 不得污染随后返回的 full。

| 请求变化 | 预期行为 |
|---|---|
| 仅切换输出视图或 values 参数位置 | 增加缓存命中，不增加完整计算和解析次数 |
| 改变调用、映射文件或显式上游链 | 使用不同上下文身份；替换旧缓存 |
| 顺序查询 A、B、A | 第三次重新计算 A，不是跨操作多条缓存 |
| 查询事实、资源清单或普通实参回溯 | 使用各自逻辑，不驱逐完整操作缓存 |
| 新进程读取相同快照 | 缓存为空；旧进程命中次数不继承 |
| 预检查失败，如上下文或文件身份不符 | 明确失败，不替换已有有效缓存 |

投影视图失败与操作计算失败要分开。例如已有完整结果的参数索引越界请求会记一次缓存命中，但投影失败；随后 full 必须仍可读取原结果。不要据此要求所有失败请求的全部计数都不变化。

资源清单本身按页重新建立结构目录。不能把完整操作缓存的收益归给清单，或把请求内自动搜索缓存当作跨进程共享。

## 从清单交接到离线证据

完整路径为：资源清单 → 显式操作概览 → 原始完整结果 → 保存实际请求和程序身份 → 关闭分析进程 → 导出 → 新进程复核。

本轮验收覆盖 XML 和注解两种映射、同资源不同调用、已知参数与未知返回并存。完整结果的条件、未知项和字节必须原样保留。局部值流中的 `formal_parameter_indices` 包含身份保持与派生依赖，不能只看 `derived_parameter_indices` 来判断是否存在形参来源。

离线成功仍只表示源码引用已核对，不表示程序关系重新验证或漏洞成立。单操作包也不替代整次清单的覆盖记录和未连接声明。输入格式与可信哈希要求见[离线交接](evidence-handoff.md)。

## 执行验收

```sh
make -f Makefile.security
python3 tests/security/test_resource_operations.py build/security/cbm-security-facts
python3 tests/security/test_operation_cache.py build/security/cbm-security-facts
python3 tests/security/test_resource_export.py build/security/cbm-security-facts
```

这些测试使用真实解析器和 MCP 进程，但只输入仓库受控源码。离线复核另启进程，不运行目标 Java、SQL、模型、网络或真实业务应用。它们证明指定样例中的接口契约，不构成漏洞基准或成本降低承诺。
