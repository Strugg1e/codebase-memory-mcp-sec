# CBM Sec 0.8 开发版：受限函数返回值摘要

本版在 0.7 的局部值流上增加函数返回摘要，继续使用六个只读 MCP 工具。
不增加模型调用、目标执行、网络、运行时依赖或数据库。输入参数不变。
本版是开发分支能力；已发布的 v0.6 Preview 1 不包含这项改动。

## 解决什么问题

```java
private long copy(long x) { return x; }
private long decorate(long x) { return x + 1; }

void handle(long id, long tenant) {
    long a = copy(tenant);
    long b = copy(0);
    sink(id, a, b, decorate(tenant));
}
```

现在分别得到：`a` 复制形参 tenant、`b` 可能为常量、最后一个实参显式依赖 tenant。
不会因为两个表达式都调用 copy，就把第一个调用的请求来源混入第二个调用。
这里描述的是值关系，不判断 sink 是否危险，不证明业务授权或净化效果。

## 首版的明确范围

仅自动选择同一个顶层普通类中直接声明的方法，调用必须无显式接收者或使用 `this`。
方法必须满足：名称唯一、实参数量与固定形参数量一致、有非 void 方法体，且满足下列之一：
`private`、`static`、`final`，或者所属类为 `final`。

暂不选择：有显式 extends/implements 的类、泛型类或方法、嵌套/匿名类、重载、变长参数、
native/abstract/synchronized 方法、其他对象接收者、类名限定调用、Object 中同名方法。
这些是当前模型范围，不是说这些 Java 写法不合法。调用适用性与类型合法性没有编译器验证。

只有选择成功才计算摘要。无法选择时保留原始调用证据，返回未知来源；
不会按名称猜测“sanitize 是安全函数”，也不会把任意外部调用默认设成实参到返回值的传播器。
类名限定的静态调用目前同样属于未覆盖写法，后续可在名称/类型消歧完善后扩展。

## 怎样计算

1. 调用者先按原局部引擎的顺序计算接收者与各个实参，逐个保存当时的值。
2. 被调用方法使用独立的局部变量环境，以自己的形参位置建立符号来源。
3. 复用局部引擎处理复制、覆盖、表达式和分支，将各个可能的 return 合并。
4. 将返回摘要中的形参位置替换为本次调用的实参来源；保留直接复制与变换依赖的区别。
5. 将被调用方法的证据编号映射到调用者证据表，并保留调用点与目标方法位置。
6. 同一操作上下文中再次调用相同方法，复用符号摘要，再独立代入实参。

缓存仅在本次操作上下文中存在，结束即释放，不跨请求或源码版本复用。
它复用的是摘要计算，不是运行结果，也不是避免整个操作的源码解析。

## 使用方式

沿用 `query_security_facts` 取得调用点编号，再调用 `inspect_operation_context`。
已有 `upstream_calls`、Mapper/XML 参数和四跳限制不变，无需手工传入返回摘要。
同一文件中符合范围的辅助方法会按需处理；后续多跳继续读取新增局部值来源。
不扫描包外文件，不执行被审计项目，不信任调用者自己填写的参数来源。

## 新增输出

`local_value_flow.return_summaries` 包含：

| 字段 | 含义 |
|---|---|
| `schema` | `cbm.java-return-summaries.v1` |
| `scope` | 当前支持的同类、不可重写方法子集 |
| `computed_methods` | 本次建立的摘要条目数，包括带缺口的条目 |
| `requests` / `cache_hits` | 实际摘要请求与命中次数，不含目标未解析的调用 |
| `total_steps` | 本次局部分析、目标选择与摘要处理共同计数 |
| `methods` | 每个摘要的方法位置、形参数量、处理的 return 数量、返回来源和证据表 |
| `truncated` | 是否触及摘要预算 |

每个摘要中 `return_relation` 的参数编号属于**被调用方法自己的形参**。
其 `evidence_ids` 引用该摘要内的 `evidence`；不会直接引用调用者的证据编号。
`arguments[i].local_value_flow` 则已经代入调用者的来源，引用顶层局部证据表。
调用者事件新增 `return_summary_target` 和 `return_summary_application`，均有准确源码位置。
不经过显式变换的复制仍沿用旧值身份定义，不证明隐式类型转换或运行时对象内容相同。

`get_snapshot_info` 新增 `return_summary_schema` 和 `return_summary_scope`。
原 v0.6 的 `arguments[i].origin`、`argument_flow.paths` 仍保持其历史直接形参语义。
新客户端读取局部值流及 `argument_flow.local_value_paths`，不要让新旧字段互相投票。

## 失败、未知和安全边界

- 未选择到唯一可处理目标：`call_return_not_modeled` 与 `return_summary_target_not_resolved`。
- 直接或间接递归：`recursive_return_summary_not_solved`；不伪称已计算不动点。
- 无可观察的正常返回或可能落出非 void 方法：`normal_return_not_established`。
- 循环、try/catch/finally 等未支持结构：保留控制缺口。即使后面返回常量，也不抹掉其中可能隐藏的 return。
- 已知分支和未知分支可以同时存在，未知部分不会被已知部分覆盖。
- 仅抛异常的方法返回未知，不把后续调用推断为“已证明不可达”。
- 缺少依赖、常量候选、方法名称以及 private/final 都不是安全结论。

摘要只计算正常返回的可能显式值依赖。不会分析堆、数组内容、库函数行为、隐式控制依赖、
路径条件真假、完整异常传播、并发、插桩或框架代理；也不生成安全规则或漏洞结论。
例如 `if(secret) return 1; else return 2` 不构造 secret 的隐式污点边。
多个分支与多个方法的组合可能丢失相关性，证据集合不是一条已证明可执行的路径。
合法 Java 源码及所声明语言子集是前提；部分反例故意仅用于测试解析器降级行为。

## 预算与资源

每次操作上下文最多 32 个摘要、8 层摘要递归、60,000 次共享处理。
每个方法原有的 20,000 次处理、64 层结构递归、256 个局部绑定/证据项继续有效。
实际限制可能先于外层上限触发；触发后保留未知与截断，不返回“干净结果”。
每份摘要只在当前上下文保存有限的参数位图和证据，不缓存整棵额外语法树。
本层使用 operation 已解析的树，不额外解析同一文件。
上游操作仍分别有自己的上下文预算，宿主需要限制完整请求和进程资源。

## 构建和验证

```sh
make -f Makefile.security
make -f Makefile.security test
python3 tests/security/test_return_summaries.py build/security/cbm-security-facts
```

新增 66 项独立测试，包括一项用 24 个固定种子的辅助方法赋值样本对照独立来源集合模型。
覆盖参数换位、覆盖与别名、分支、正常/未知返回、递归、缓存隔离、预算、准确引用和两跳组合。
原有 332 项测试保持。本轮所有通过状态必须以实际构建日志为准，测试存在不代表已通过。
未执行真实 Codex/Sulliu 审计，也不据此报告召回率、准确率或 Token 收益。

开发依据（仅开发核对，运行时不访问）：Java SE 25 语言规范 8.4.3、14.17、15.12.4。
https://docs.oracle.com/javase/specs/jls/se25/html/jls-8.html
https://docs.oracle.com/javase/specs/jls/se25/html/jls-14.html
https://docs.oracle.com/javase/specs/jls/se25/html/jls-15.html
