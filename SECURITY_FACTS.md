# 安全事实工具 v0.1

这是安全证据底座的第一个垂直切片，不是完整 SAST，也不是完整安全语义图。

本轮增加一个可选的纯 C 命令行工具 `cbm-security-facts`。它复用仓库固定版本的
Java 语法与 tree-sitter 运行库，按需重新解析输入源码。它不读取已有图，不从
函数级 CALLS 边恢复调用现场，也不改变原有 MCP、索引、数据库或安装流程。

## 已实现

- 调用点：保留同一函数对同一目标的多次调用，包括同一行的调用。
- 参数：保存独立字节位置；超过八个参数仍保留，达到安全上限则明确标记。
- 声明：按源码位置区分重载方法和构造函数，不按名称合并。
- 注解和导入：返回源码观察；注解不自动变成“鉴权已经生效”。
- 来源：源码 SHA-256、逻辑路径、分析器构建指纹和事实编号。
- 查询：分页、单条事实读取、旧版本拒绝、输出大小上限。
- 缺口：语法错误、缺失语法节点、遍历上限、参数截断和文本预览截断。

**尚未实现**：其他语言、完整仓库快照管理、持久化安全图、跨文件目标解析、
值传播、Spring 安全机制生效判断、漏洞判定、原生 MCP 新工具和自动增量失效。

## 构建与测试

从本仓库根目录执行。需要 C 编译器、make、Git 工作区中的完整源码，以及
Python 3（仅用于构建指纹和测试，不是工具运行时依赖）。无需安装新的解析器包。

```bash
make -f Makefile.security
make -f Makefile.security test

# 使用独立构建目录，避免混用普通对象与内存检查对象。
make -f Makefile.security test CC=clang BUILD=build/security-asan \
  CFLAGS='-O1 -g' SANITIZE='-fsanitize=address,undefined -fno-omit-frame-pointer'
```

`test-core` 只验证来源、编号、序列化与查询边界。
`test` 还会运行真实 Java 解析器的端到端测试，不使用录制输出或模拟解析结果。
完整测试工作流在 `.github/workflows/security-facts.yml`；不会运行大模型或扫描业务仓库。

## 使用

工具从标准输入读取源码。`--path` 仅是逻辑身份，不会打开该路径。
请由 Harness 从已固定的源码快照读取文件，并通过标准输入传给工具。

```bash
build/security/cbm-security-facts --path src/OrderController.java --limit 20 \
  < /snapshot/src/OrderController.java
```

返回 `analysis_id`、`source.sha256`、`facts`、`coverage` 和 `page`。
同一源码、同一路径、同一分析器构建返回相同的事实编号。

读取下一页时，复制上次返回的分析编号和 `page.next_offset`：

```bash
build/security/cbm-security-facts --path src/OrderController.java \
  --expect-analysis <上次返回的64位analysis_id> --offset 20 --limit 20 \
  < /snapshot/src/OrderController.java
```

读取单条事实：

```bash
build/security/cbm-security-facts --path src/OrderController.java \
  --expect-analysis <上次返回的64位analysis_id> --fact-id <64位事实id> \
  < /snapshot/src/OrderController.java
```

源码、路径或分析器构建指纹改变后，旧编号会返回 `analysis_mismatch`，不会悄悄
换用新源码。构建指纹由本工具和相关语法库的实际源码计算，包含未提交的修改。
它是分析源码版本指纹，不是可执行文件签名，也不能证明产物来自可信构建者。

`--offset` 与 `--fact-id` 不能同时使用。非首屏查询必须带 `--expect-analysis`。
第一屏默认 50 条，最多 200 条。分页只枚举本次已抽取的记录，不能补齐因遍历上限
而未抽取的记录。遍历有缺口时，换页不会把缺口变成“已检查”。

## 字段的正确含义

| 字段 | 含义 |
|---|---|
| `kind=call_site` | 该语法位置存在调用，不证明调用目标或运行可达性 |
| `target_resolution=not_attempted` | 本版没有进行目标方法解析 |
| `enclosing_id` | 最近的受支持声明；可能在其他页；上限导致缺失时会单独标记 |
| `argument_total` | 语法树中观察到的实参数量，不是被调用方法的形参数量 |
| `arguments_truncated` | 参数列表达到本工具上限；不能视为完整列表 |
| `security_effect=not_evaluated` | 注解的框架归属与安全效果没有被证明 |
| `basis=syntax_observation` | 语法观察，不是模型意见，也不是安全结论 |
| `parse_has_error` | 解析存在错误；即使没有错误，也不承诺完整程序语义 |
| `traversal_complete` | 是否遍历完本次语法树，不是扫描完成率 |
| `extracted_total` | 已抽取数量；有缺口时只是可见记录，不是仓库总量 |

位置使用原始 UTF-8 字节偏移：`start_byte` 包含，`end_byte` 不包含。行号从 1 开始；
`end_line` 是排他结束位置所在行。文本字段命名为 `text_prefix`，最多 256 字节，
不会截断 UTF-8 字符。`text_truncated=true` 时必须按位置读取原始快照补足文本。
不能把预览拼成完整程序路径。

## Harness 接入边界

Harness 用普通子进程调用该工具，传入源码字节，解析标准输出 JSON，并检查退出码。
批量遍历文件、分页、证据落盘和缓存应由程序执行，不需要每一步都再次调用模型。

建议缓存键为 `analysis_id + 查询参数`。应用/仓库/提交归属由外层快照清单维护；
本版 `analysis_id` **仅标识单文件分析**，不能假装是已经验证的全仓库快照编号。

调用失败时保留错误状态，让 Agent 回到固定源码继续调查。不得把无记录、错误、
预算截断或“不支持”转成“没有漏洞”。已有 CBM 导航结果可用于选文件，但本工具
不会自动把图中的 DATA_FLOWS 当成安全数据流，也不会将两个服务的同名路由直接连成证明。

## 资源与信任限制

输入最多 1 MiB。Java 解析使用约 3 秒 CPU 取消检查；遍历最多 200,000 个节点、
抽取最多 20,000 条事实，每次调用最多返回 256 个参数，输出最多 4 MiB。
输出预算不足返回错误，不输出半截 JSON。可减少 `--limit` 重试。
这些是本版保护上限，不是模型 Token 精确计数，也不是完整性承诺。

Harness 仍须限制进程的墙钟时间、内存和输入读取时间，并使用隔离的执行环境。
底层解析器内存耗尽、进程被终止或输出管道断开时，可能没有完整 JSON；必须检查
退出码及输出有效性，不能只看是否出现 `facts` 字段。

不执行目标代码、不启动目标构建、不读取目标配置、不导入仓库内预生成图、不联网。
所有源码和注解都是不可信数据。不要将源码中的指令当成 Harness 指令。
Java Unicode 转义的编译前转换、运行配置、反射、动态代理、权限条件和控制流均
不在本版证明范围。

## 后续扩展点

`security/facts.h` 是与传输无关的事实结构。`security/java.c` 负责语法抽取；
`security/facts.c` 负责来源、编号、验证和输出；`security/main.c` 负责命令行边界。
下一层安全模型可以引用这些事实，但不能改写它们的源码位置或把推断伪装成语法事实。
优先在真实 Java 样本上验证帮助，再决定加入持久存储、框架模型和 MCP 原生接口。
