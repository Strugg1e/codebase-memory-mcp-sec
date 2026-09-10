# 安全证据 MCP v0.4

本版新增独立的纯 C 可执行文件 `cbm-security-mcp`，把已有证据核心接到只读 MCP。
它不是对原有 CBM MCP 服务直接加工具；原有导航图、数据库、安装器和主构建保持不变。
`cbm-security-facts` 的单文件 CLI 继续可用，原有字段与框架范围见 `SECURITY_FACTS.md`。
该文件中的 v0.3“尚无 MCP”边界描述的是旧版；新增服务以本文为准。

## 实际工作方式

```text
已有固定只读源码快照
    → 可信调用方明确选文件
    → 打成带逐文件哈希的源码包
    → 可信配置固定整个包的 SHA-256
    → MCP 启动时校验并把源码保存在内存
    → Agent 按需列文件、筛事实、读证据、补源码
```

这里的快照是一个**明确选择的文件集合**，不声称它覆盖整个仓库。它不运行 Git，也不创建
业务仓库的原子提交快照。调用方必须先准备不可变或只读的源目录，并保存仓库/提交/任务归属。

服务启动后不会重新打开源码包、目标路径或目标配置。即使磁盘上的源码包被替换或删除，
查询仍使用已校验的内存字节。换源码必须重启进程并提供新的包哈希，不能通过工具请求换根目录。
源码包可以包含不支持分析的 UTF-8 文本文件；清单会标记它们，查询返回 `unsupported_language`，
仍可按字节读取这些文件。二进制、含 NUL 或无效 UTF-8 输入拒绝，不静默丢弃。

## 五个只读工具

| 工具 | 用途与边界 |
|---|---|
| `get_snapshot_info` | 返回快照编号、文件数、可分析文件数和真实缓存计数；不是安全覆盖率 |
| `list_snapshot_files` | 分页列出包中的所有文件，包含不支持分析的文件；不会扫描磁盘 |
| `query_security_facts` | 按 `kind/framework/role/enclosing_id` 精确取交集；沿用原有事实和覆盖信息 |
| `get_security_evidence` | 用快照、路径、分析编号和事实编号读取单条证据 |
| `read_snapshot_source` | 用路径、文件哈希和字节范围补读源码，最多 16 KiB，不截断字符 |

除 `get_snapshot_info` 外，都要求 `snapshot_id`。查询路径必须已在包中。
`get_security_evidence` 还要求 `analysis_id`、`fact_id`；`read_snapshot_source` 要求
`sha256`、`start_byte`、`end_byte`。起点包含、终点不包含，必须落在 UTF-8 字符边界。

事实查询每页默认 20 条，上限 200。`query_security_facts` 的可选 `expect_analysis` 可预先
校验分析编号。所属声明查询仍只查询直接归属，不自动证明类级或全局控制适用。
权限注解、中间件和守卫仍只是候选声明；没有改成“控制已生效”或“漏洞已确认”。

分页使用返回的 `page.next_cursor`，并重复原筛选。MCP 游标额外绑定整个源码包身份，
不能跨快照、跨文件或跨查询条件混用。它与单文件 CLI 游标不是相同协议；不要混用。
文件清单使用自身返回的 `next_cursor`。游标不是签名或访问凭据。

## 构建与试用

从可信的本工具工作区执行，不从被审计目录加载脚本。需要 C 编译器、make 和 Python 3。
Python 只负责构建、可选打包和测试；MCP 与 CLI 本身都不依赖 Python 运行时。
JSON 复用仓库已有的 yyjson，不下载或添加新库。

```bash
make -f Makefile.security
make -f Makefile.security test
```

下面是 POSIX 示例。先把 `/snapshot` 和文件清单替换为实际只读快照及所需文件。
输出目录必须在目标快照之外，权限仅授予分析工作进程。

```bash
set -eu
umask 077
WORK="$(mktemp -d)"
printf '%s\n' '["app/api.py","src/routes.ts"]' > "$WORK/files.json"

python3 security/pack_snapshot.py --root /snapshot --files "$WORK/files.json" \
  > "$WORK/snapshot.json" 2> "$WORK/snapshot.sha256"
SNAPSHOT_ID="$(cat "$WORK/snapshot.sha256")"

# 此命令启动 stdio 服务；标准输入必须是 MCP 消息，不是源码。
build/security/cbm-security-mcp \
  --snapshot "$WORK/snapshot.json" --expect-snapshot "$SNAPSHOT_ID"
```

打包器不遍历目录，不读取目标的忽略规则、Agent 指令或配置。只读可信调用方给出的路径列表。
逐层使用目录文件描述符及禁止跟随链接的打开方式，拒绝符号链接、多硬链接、管道和非普通文件。
检测到读取期间的文件变化会失败。这个检查不能把可变目录变成原子多文件快照；源目录仍须由外层冻结。
`--root` 及其祖先目录、清单位置、工具路径都是可信启动配置，不由目标仓库决定。

成功时标准输出是完整 JSON，标准错误仅输出它的 SHA-256。失败返回非零，不继续启动服务。
不要在失败后复用旧哈希。源码包包含完整源码，应按原始源码保护，不提交到公开仓库。

### 接入 Codex / 其他 Harness

下面是 Codex 的 stdio 配置示例，不会由本工具自动修改用户配置。替换绝对路径和实际 64 位哈希：

```toml
[mcp_servers.cbm_security]
command = "/trusted/tools/cbm-security-mcp"
args = ["--snapshot", "/private/artifacts/snapshot.json", "--expect-snapshot", "替换为实际64位SHA256"]
startup_timeout_sec = 20
tool_timeout_sec = 30
```

正式使用应把源码包放到任务生命周期内稳定的私有产物路径，不能依赖随时清理的临时目录。
支持 stdio 的其他 Harness 使用相同可执行文件和启动参数。服务只有这一进程内的源码集可读，
没有网络监听、外部凭据、Shell 工具、运行目标或文件写接口。

建议第一次接入采用以下任务回放：

```text
get_snapshot_info
→ list_snapshot_files
→ query_security_facts（选路径与路由类别）
→ get_security_evidence（取一个编号）
→ read_snapshot_source（读取对应片段）
→ Agent 继续检查，而不是把框架标注直接写成漏洞
```

上述配置方式参考 OpenAI 官方 MCP 文档；本轮自动测试不启动 Codex、不调用模型 API。
真实 Codex 会话兼容性、召回、准确率、耗时及 Token 收益需要另行在相同任务条件下评测。

## 缓存和失败状态

服务只保留**最近一个文件**的解析结果，避免无界内存缓存。相同文件的连续分页、筛选和单条
证据读取不重复解析；切换文件会替换缓存，再切回时重新解析。缓存仅在当前进程有效。
`get_snapshot_info.cache` 返回 `parse_attempts`、`hits`、`failed_files`，不使用模拟计数。

版本或查询不匹配在解析前拒绝。一次解析失败会记录在该文件上，当前进程不反复重试同一输入；
需要重试时由 Harness 重启服务。语法/遍历有缺口但仍有合法部分结果时，保留其覆盖字段。
工具错误返回 `isError=true` 及稳定错误码，未知工具/方法返回协议错误。
空结果、不支持、预算停止、服务退出均不能转成“无漏洞”。

## 协议和资源限制

MCP 使用换行分隔的 JSON-RPC stdio，支持协商 `2025-11-25` 与 `2025-06-18`。
有初始化握手、工具发现、工具调用、ping、正常 EOF 退出；没有 HTTP、资源订阅、模型采样或任务扩展。
不支持后续协议的无握手模式。客户端请求未知版本时返回本服务支持的版本，由客户端决定是否继续。

请求按顺序执行。`notifications/cancelled` 不会中断已经同步执行的解析；没有宣称支持异步取消。
Harness 必须设置墙钟和内存限制；需要立即中止时终止工作进程，再以同一包重建服务。
关闭输入可正常退出，但 EOF 要等当前有界请求结束。宿主不得把“发送了取消通知”展示成“已取消”。

| 限制 | 本版值 |
|---|---:|
| 源码包文件数 | 1,024 |
| 单文件源码 | 1 MiB |
| 全包解码后源码 | 16 MiB |
| 包文件编码后大小 | 32 MiB |
| 单条 MCP 输入 | 32 KiB |
| 输入 JSON 嵌套 / 单对象键数 | 32 / 32 |
| 单次源码补读 | 16 KiB |
| 单文件事实与遍历 | 20,000 条 / 每次主要遍历 200,000 节点 |
| 一页事实 | 最多 200 条 |
| 原始事实 JSON | 最多 4 MiB |
| MCP 序列化响应 | 最多 64 MiB，包含结构化和文本兼容副本 |

大输出仍可能超过模型上下文预算，优先使用较小页和精准筛选。MCP 同时返回 `structuredContent`
和文本 JSON，Harness 应选用一种表示，避免把两份相同内容都放进模型上下文。
超长输入直接关闭连接；无效 JSON、重复键、嵌入 NUL 和过深结构被拒绝。
这些是实现上限，不是整个进程内存上限。底层解析器分配失败或进程被终止可能没有完整响应。

包 SHA-256 校验用于内容固定，不是签名、租户认证或可信来源证明。预期哈希必须来自可信控制面，
不能把目标仓库附带的包及它自带的哈希不经审核直接作为证据。服务不会导入预生成事实图。

## 验证与未实现范围

`tests/security/test_mcp.py` 通过真实子进程测试握手、五个工具、所有六套解析器与 CLI 等价性、
缓存、分页绑定、原始字节、旧版本拒绝、输入边界及启动失败。还测试打包器的路径和链接反例。
是否已通过请查看当前提交的 CI 日志，测试代码存在不等于已执行。

本版不新增语言或框架，不实现跨文件解析、值传播、完整安全图、全仓扫描、增量图更新、部署策略、
安全控制生效或漏洞判定。没有自动把服务接进 Sulliu，也没有修改其生产配置。

官方参考：
- https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle
- https://modelcontextprotocol.io/specification/2025-11-25/basic/transports
- https://modelcontextprotocol.io/specification/2025-11-25/server/tools
- https://developers.openai.com/codex/mcp/
