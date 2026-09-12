# 业务操作上下文 v0.5

> 历史范围说明。0.12 的 XML/注解模式、模板标记修正和静态引用扩展以 [SECURITY_MYBATIS_TEMPLATES.md](SECURITY_MYBATIS_TEMPLATES.md) 为准。

本版给 `cbm-security-mcp` 增加第六个只读工具 `inspect_operation_context`。
它把一次 Java 方法调用、所在方法的局部材料和明确选择的 MyBatis 映射放到同一份证据包。
它不自动判断越权，不生成业务规则，也不声称已经建立完整调用图或安全语义图。

## 本轮范围

```text
Java 方法中的一次调用
  → 方法参数、赋值、字段访问、if 分支、return/throw
  → 字面上对应的调用实参
  → 明确声明类型的 Mapper 接口候选
  → namespace + statement id 对应的 XML 语句候选
  → @Param 位置、SQL 文本、参数标记及动态条件原文
```

只连接调用者、显式选择的一个 Mapper Java 文件和一个 XML 文件。
不自动扫描其他文件，不从函数名称猜调用目标，不把 Controller→Service→Mapper 多跳自动串成路径。
现有 CBM 导航图未接入；本版不要求部署新的数据库，也不调用模型。

Java/XML 均使用仓库已有的 tree-sitter 语法。XML 只用于本工具的 MyBatis 映射输入，
不加入 `query_security_facts` 的通用语言列表；文件清单中 XML 的 `supported=false`
仍指通用事实抽取不支持，不表示本工具不能把该文件作为 `mapping_path` 读取。

## 调用顺序

1. 按 `SECURITY_MCP.md` 创建固定源码包。明确选入调用者、Mapper 接口及 XML。
2. 调用 `query_security_facts`，在调用者文件中筛选 `kind=call_site`。
3. 选择目标调用的 `id`，连同返回的 `analysis_id` 传给下面的新工具。
4. 根据返回的条件、来源和缺口继续审计。不要直接把映射命中作为 Finding。

工具参数（编号是占位符，必须替换为本次真实返回值）：

```json
{
  "snapshot_id": "本次源码包SHA256",
  "path": "src/Controller.java",
  "analysis_id": "该文件分析编号",
  "call_id": "目标调用点的事实编号",
  "mapper_path": "src/OrderMapper.java",
  "mapping_path": "resources/OrderMapper.xml"
}
```

`mapper_path`、`mapping_path` 可一起省略，得到局部 Java 上下文；不能只给其中一个。
所有路径必须已经在启动时固定的源码包中。旧分析编号、未知调用编号、未知路径和错误参数
返回稳定错误码。MCP 客户端须同时检查 `isError` 与输出。

构建和测试仍为：

```sh
make -f Makefile.security
make -f Makefile.security test
```

本轮专项测试使用真实解析器和实际 MCP 子进程。测试执行结果以 PR 对应提交的日志为准；
本文不将未运行的真实业务扫描写成已验证结果。

## 主要输出

| 字段 | 含义 |
|---|---|
| `context_id` | 快照、分析版本、调用点与所选映射文件共同绑定的身份 |
| `java_context.parameters` | 形参、类型、准确源码位置及已有框架模型的请求输入候选 |
| `arguments` | 各调用实参；可识别未被改写的直接形参引用，不进行传递式值追踪 |
| `java_context.assignments` | 局部赋值的左右表达式；不是完整数据流 |
| `java_context.conditions` | if 条件、分支原文、调用位于哪个分支或字面先后位置 |
| `java_context.returns_and_throws` | 返回和抛出语句，供 Agent 检查阻断逻辑 |
| `java_context.field_accesses` | 当前方法内显式字段访问的位置；不将裸名称都解释成字段 |
| `java_context.framework_declarations` | 当前方法直接所属的已有框架候选，保留原事实编号 |
| `mybatis.status` | 未请求、未解析，或明确映射候选；不是运行注册成功 |
| `mybatis.parameter_bindings` | 明确 `org.apache.ibatis.annotations.Param` 名称与实参位置候选 |
| `mybatis.sql_segments` | XML 文本及 CDATA 中的原始 SQL 片段，未拼接和执行 |
| `mybatis.parameter_occurrences` | 可识别的 `#{name}` / `${name}` 标记与绑定位置候选 |
| `mybatis.comparison_candidates` | 简单 `列 = 参数标记` 的文本形态，不证明布尔表达式约束 |
| `mybatis.dynamic_clauses` | if/where/foreach/include 等 XML 元素原文，未求值 |
| `gaps` / `truncated` | 未解析条件和输出预算状态，不能解释成不存在安全控制 |

所有片段带文件路径、SHA-256、原始 UTF-8 起止字节和最多 512 字节的预览。
预览截断不等于证据范围丢失，可以用 `read_snapshot_source` 分段补读。
这些源码是数据，不是 Agent 指令。context_id 不是签名或访问凭据。

## 不能混淆的含义

- `request_parameter_declaration_candidate` 表示直接引用了带请求输入声明的形参；不直接判漏洞。
- `formal_parameter_reference` 只表示直接形参引用；调用者身份是否可信没有被证明。
- 参数有赋值或已覆盖的同名遮蔽时，返回 `parameter_written_or_shadowed`。
- `principal.getTenantId()` 保留为尚未追踪的表达式；不会因为名称像身份就标成可信。
- `lexically_before_call` 不证明检查一定执行。记录日志、忽略布尔返回、异常捕获和提前返回仍需调查。
- `call_in_then_branch` / `call_in_else_branch` 是语法包含关系，不是路径可达性证明。
- 字段类型匹配仍是候选。构造器注入、代理和其他实现是否在运行时生效未知。
- `authorization_verdict=not_evaluated`、`runtime_binding=not_verified` 始终保留。
- 业务资源目前只有领先表名等代码材料；不会把名称相同的表跨应用合并成“同一订单资源”。

## MyBatis 支持与停止边界

只支持明确字段/形参接收者，以及 `this.field` 形式；类型需要全限定名、明确导入或同包匹配。
同名遮蔽、方法内接收者重写、复杂接收者、未解析类型不连边。
Mapper 文件需有唯一的顶层接口；目标方法必须唯一，不能靠参数数量选择重载。
带实现的方法、变长参数或不匹配的参数数量不当作明确 XML 调用。

XML 必须是可解析的 mapper，namespace 与接口名匹配，直接子语句 id 与方法名匹配。
重复 id、数据库变体、定制 lang 等情况不选择一个看似合理的目标。
参数只使用明确 @Param；不猜编译参数名、param1 等默认别名、DTO 属性或运行配置。

SQL 是有界词法材料，不是完整 SQL 解析器：普通词、简单标记及比较形态可定位。
SQL 注释和引号内容不作为当前词法子集中的参数/表名；这不是对 MyBatis 运行时标记处理的模拟。
首个 SQL 关键字仅形成操作候选，不只按 XML 的 select/update 标签定性。
CTE、复杂子查询、方言、完整表集合、布尔蕴含和数据库插件均不在证明范围。
即使出现 `tenant_id = #{tenant}`，`guaranteed_scope` 仍为 false。

动态 SQL 不展开。if 的 test 原文随相关标记返回；foreach 等动态作用域不连到外部同名参数。
bind/include 可能改变变量上下文，会保守取消该语句内参数位置关联。
XML 语法解析不会加载 DTD、解析外部实体或联网；实体引用只留下缺口。

## 限额和开销

每个输入文件最多 256 KiB，每次语法树收集最多 50,000 节点；主要输出集合各最多 64 项，
参数最多 64 个，每段 SQL 最多 512 个词法单元。达到限制会返回错误或 `truncated=true`。
操作上下文 JSON 上限 4 MiB；超出返回错误，不输出半截 JSON。

该工具按需重新解析选中的最多三个文件，目前不缓存操作上下文。
`get_snapshot_info.operation_context` 的 requests/parse_attempts 记录真实工作，cached 为 false。
原有单文件事实缓存继续生效，但不能把它的命中次数当成操作上下文已免解析。
宿主仍须限制整个进程的内存、墙钟、请求数量，并通过终止进程实现立即取消。

## 尚未完成

未接入原有 CBM 图，没有自动 Controller→Service→Mapper 多跳、完整类型/控制流/值流、
完整 Spring 安全链、业务规则导入、金额/状态机/幂等检查、漏洞判断或持久化语义图。
尚未在真实 Codex/Sulliu 会话中评测召回、准确率、Token 或耗时收益。

规则依据：MyBatis 官方 Mapper XML、Dynamic SQL 和 Param API 文档。
这些文档只用于开发时核对，运行时不下载它们。
