# CBM Sec 0.7 开发版：局部值来源与多跳组合

本版基于已发布的 `cbm-sec-v0.6.0-preview.1`，继续使用六个只读 MCP 工具。
不修改主程序、目标源码、既有 Release 标签、Sulliu 或 Codex 配置。不调用大模型。

## 本轮解决的问题

v0.6 只跟进未被改写的直接形参引用。例如 `alias=tenant` 会停止追踪。
v0.7 增加一个共享的局部分析模块，将局部变量、赋值覆盖、分支合并和表达式依赖计算好，
再沿 v0.6 已核对的显式调用关系组合。它不是完整的 Java 污点引擎。

```java
long alias = tenant;             // alias 来自形参 tenant
if (condition) alias = id;       // 合并后可能来自 tenant 或 id
mapper.load(id, alias);          // 保留两个可能来源，不挑选其中一个
```

```java
tenant = 0;
mapper.load(id, tenant);         // 这次调用的 tenant 不再沿用覆盖前的形参来源
```

“来源集合为空”或“来自字面量”都不是安全结论。查询只描述所支持模型下的局部值关系。

## 输入没有变化

仍通过 `query_security_facts` 获取 Java 方法调用的 `analysis_id` 和 `call_id`，
随后调用 `inspect_operation_context`。`mapper_path` 和 `mapping_path` 仍须一起提供或省略；
可选 `upstream_calls` 仍为最近调用者在前，最多四个调用点。

`get_snapshot_info` 增加 `local_value_flow_schema` 和 `local_value_flow_scope`，
MCP 工具说明也说明新旧结果的区别。通用 CLI 不做这个操作分析，其旧能力标记没有提升。

## 新输出与旧字段兼容

| 字段 | 用途 |
|---|---|
| `local_value_flow` | 本次局部分析的范围、状态、缺口、预算及证据表 |
| `arguments[i].local_value_flow` | 第 i 个实参的可能来源、变换依赖、字面量可能性和未知部分 |
| `argument_flow.local_value_paths` | 仅沿已接受调用候选组合的新来源集合；旧 `paths` 不变 |

原来的 `arguments[i].origin`、`argument_flow.paths` 仍按 v0.6 的直接形参规则返回。
例如旧字段对局部别名仍是 `expression_not_traced`，新字段可以保留已解析的别名链。
两套字段的分析范围不同。新客户端应读取新字段；不要对两套结果投票或把旧停止原因当成新结果。
`argument_flow.taint_transformations=not_modeled` 是旧直接引用投影的历史字段，
不代表新增局部分析没有表达式依赖；新字段也没有宣称完整的风险类型相关污点规则。

每个实参的主要内容：

- `formal_parameter_indices`：全部已知的显式形参依赖，按位置而非名字对应。
- `value_identity_parameter_indices`：不经过显式变换的局部复制候选。
- `derived_parameter_indices`：经过算术、拼接、复合赋值、类型转换等的依赖。
- `literal_possible`：抽象模型中的字面量/常量表达式可能性，不保存或证明具体常量值。
- `unknown_reasons`：不能建立关系的部分。已知来源和未知部分可以同时存在。
- `evidence_ids`：引用本层 `local_value_flow.evidence` 的编号，作用域仅限本次上下文。

多跳组合丢失分支相关性，因此结果是可能依赖的过近似；常量标记也可能过近似。
不能把多个来源、两个分支或不同调用场景拼成一条已证明可执行路径。
`formal_parameter_context_layer` 表示最终来源编号属于根层 0 还是第几个上游上下文。
多跳步骤保留每层输入参数位置及其局部证据编号；根参数证据单独保存。
证据是依赖材料集合，不是执行轨迹。所有源码引用仍有路径、SHA-256 和准确 UTF-8 字节范围。

## 已支持的 Java 子集

局部声明与多变量初始化、块作用域、直接复制、顺序覆盖、普通/复合赋值、括号、显式转换、
一元与二元表达式、算术与字符串拼接、自增自减、if/else、三元表达式、&&/|| 的条件副作用合并，
以及 return/throw 后不再正常流入后续语句。

调用的接收者和实参按顺序处理；前面实参的值不受后面实参内赋值的回溯影响。
如 `sink(tenant, tenant=0, tenant)`，第一个参数仍引用旧值，后两个来自字面量。
带限定对象的创建表达式，例如 `(x=y).new Inner()`，会先处理限定对象中的赋值。

不求解条件真假、不枚举可执行路径、不执行常量折叠、不验证编译/类型合法性。
在合法 Java 源码与声明子集假设下，输出描述局部值身份和显式依赖，不是完整语言证明。
异常、隐式转换、动态派发、运行配置及并发仍不在证明范围。

## 未支持部分如何处理

- 任意函数返回值不默认依赖全部实参，返回 `call_return_not_modeled`。
- 字段和数组元素读取返回 `heap_contents_not_modeled`。复制一个对象引用不等于追踪对象所有内容。
- 循环、try/catch/finally、switch、标签、断言等未支持控制结构不按源码行号强行展开。
  它们在目标调用之前出现时，将当前局部状态标为可能受未知影响；目标调用位于其中时，
  返回 `anchor_not_evaluated`。不把没追到当成安全。
- 未支持表达式可能包含赋值，因此也会使当前局部状态出现未知项，不静默保持旧值。
- lambda 创建不会执行其函数体。位于 lambda 内的调用仍受原操作锚点支持范围限制。
- 原始 `\\u` 转义、变长/特殊形参、预算耗尽都有明确缺口。
- 不跟踪隐式控制依赖。例如 `if(secret) a=1; else a=2` 不建 secret→a 污点边，
  元数据始终标记 `implicit_flows=not_modeled`。

## 实现与限制

新增 `security/local_flow.c/.h`，在 `operation.c` 已解析的 Java 树上工作，不额外解析同一方法。
上游操作复用相同模块；`flow.c` 仅在既有调用校验通过后组合这些结果。
没有新增解析器、数据库、网络或运行时依赖，没有自动调用者发现，也没有新缓存。

局部分析上限：64 形参/实参、256 活跃局部绑定、256 个证据项、20,000 次节点处理、64 层递归。
分支在结构上合并，不复制完整路径集合。事件、变量或深度超限保留 `truncated` 和未知状态。
原操作文件 256 KiB、输出 4 MiB、四个上游调用点等限制继续有效，宿主仍需限制进程资源。

## 构建与验证

```sh
make -f Makefile.security
make -f Makefile.security test
# 仅运行本轮测试
python3 tests/security/test_local_flow.py build/security/cbm-security-facts
```

原 266 项测试保持不变。本轮 `test_local_flow.py` 新增 66 项不同测试，其中一项包含
32 个固定随机种子的直线赋值程序，与独立 Python 来源集合模型对照；不是 32 次重复计数。
另含别名、覆盖、分支、提前退出、短路、求值顺序、字段/数组/未知调用、UTF-8 位置、预算、
多跳换位、多来源和未知链路等反例。测试均通过真实 C 解析器和 MCP 子进程。
是否通过远程 CI，以对应提交的任务日志为准，不能从测试代码存在推断已通过。

本轮不发布新的 Release，也不替换 v0.6 预览包。真实业务仓库、Codex/Sulliu 会话、
Windows/macOS 和审计召回/准确率/成本收益均需单独验证。

开发时核对的语义依据（运行时不访问）：
- Java 语言规范第 14 章：https://docs.oracle.com/javase/specs/jls/se25/html/jls-14.html
- 第 15.7 与 15.26 节：https://docs.oracle.com/javase/specs/jls/se25/html/jls-15.html
