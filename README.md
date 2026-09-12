# CBM Sec

**面向安全审计 Agent 的静态程序分析内核与证据查询服务。**

CBM Sec 把固定源码中的入口、调用现场、参数关系、数据操作和安全配置整理为可引用的分析材料。
Agent 用这些材料继续调查；宿主平台管理任务、业务要求、反证和漏洞结论。

当前为 **`0.13.0-dev` 开发版**。已有受限的 Java 值流和框架关系分析，
**尚无自动、通用的输入源到危险点追踪能力，也不是完整 SAST 平台。**

本项目派生自 [codebase-memory-mcp](https://github.com/DeusData/codebase-memory-mcp)，
复用其语法库与基础组件；安全分析使用独立的 `security/` 模块、构建入口和可执行文件。
它不是给原版 MCP 简单增加几个工具，也没有直接接通原版的持久化代码图。

## 先选对版本

| 位置 | 内容 |
|---|---|
| `feat/security-facts-v0.1` | 本 README 对应的安全开发分支；功能与限制以该提交为准 |
| `main` | 安全功能尚未合入，仍是上游基线，不能从这里直接构建本页所述开发功能 |
| [0.6.0 Preview 1](https://github.com/Strugg1e/codebase-memory-mcp-sec/releases/tag/cbm-sec-v0.6.0-preview.1) | 已发布的历史预览包，不含后续开发功能 |
| [PR #1](https://github.com/Strugg1e/codebase-memory-mcp-sec/pull/1) | 开发变更与验证记录；草稿不是已发布稳定版 |

不要用原版 CBM 的安装脚本安装安全工具。项目名称、仓库地址、可执行文件名和协议编号目前保留，
避免仅因产品定位调整而破坏现有调用。

## 能提供哪些证据？

| 能力 | 已实现的范围 | 不能据此推断什么 |
|---|---|---|
| 多语言语法事实 | Java、Python、JavaScript、TypeScript、TSX、Go 的调用点、参数、声明、导入等 | 支持解析不等于具有同等值流分析能力 |
| 框架声明 | Java/Jakarta、Spring/MyBatis/JPA、Python Web/DRF、Express/NestJS/Fastify、Go HTTP/Gin/chi/Echo 的文档化写法 | 声明存在不等于运行时启用；具体范围见框架文档 |
| Spring MVC 入口 | 直接类级与方法级映射、处理函数、输入和控制声明；快照内有界分页 | 不证明实际注册、外部访问地址或全部入口覆盖 |
| Java 局部值流 | 受限的变量复制、覆盖、表达式依赖、分支合并 | 不是完整控制流、堆、数组或隐式流分析 |
| Java 返回摘要 | 同一顶层普通类中符合限定条件的辅助方法；按调用实参组合返回依赖 | 不支持任意跨文件返回或动态分派 |
| 显式多跳 | 调用方提供最多四个上游调用点；程序逐跳核对声明类型和参数位置 | 不是自动发现整条调用链；候选连接不等于路径可执行 |
| MyBatis 操作 | 明确 Mapper 的 XML 或有限注解模板、`#{...}`/`${...}`、动态条件、同命名空间静态引用及参数关联 | 不执行模板表达式、Provider 或数据库；不直接判 SQL 注入或租户隔离 |
| Spring Security 关系 | 显式配置范围内的过滤链、规则顺序、忽略配置与条件选择 | 不证明配置注册或对象授权；路径匹配仅支持文档限定子集及明确假设 |
| 固定版本与引用 | 启动时校验所选文件包，查询引用绑定哈希、分析版本和 UTF-8 字节范围 | 所选文件集合不是全仓库完整覆盖证明 |
| Agent 上下文 | `summary`、`values`、`full` 视图；完整证据可以回取 | 精简响应不等于免去分析成本，也不是实际 Token 收益评测 |

完整框架范围见 [SECURITY_FRAMEWORKS.md](SECURITY_FRAMEWORKS.md)。
二进制的 `--capabilities` 和 MCP 的 `get_snapshot_info` 返回同一份产品能力表。

## 能完整追踪 Source → Sink 吗？

**还不能。当前是“对已选操作和已给定调用路径进行有界取证”，不是“自动从全仓库寻找危险流”。**

这里的输入源（Source）指被分析规则认定的不可信输入位置；危险点（Sink）指该风险类型关心的操作或参数位置。
HTTP 路由不自动等于所有输入源，任意调用或数据库操作也不自动等于危险点。

当前可以：选择一次 Java 调用，检查它的实参来源；在已支持的局部语法和显式上游路径内继续关联；
对于明确的 MyBatis 映射，连接查询模板标记与调用参数。结果同时保留前提、未知项和停止原因。

要形成自动、可复用的源到点分析，还缺少以下共同能力：

| 环节 | 当前状态 |
|---|---|
| 统一的输入源、危险参数、传播与净化规则目录 | 尚未形成通用的、可配置的风险规则层；现有框架声明和模板标记是基础材料 |
| 自动目标解析与路径发现 | 上游调用、Mapper 和安全配置仍需明确选择；未接入实时 CBM 图 |
| 更广的值传播 | 循环收敛、完整异常、堆与数组内容、跨文件返回和外部库模型仍有缺口 |
| 风险相关的阻断关系 | 没有通用净化或校验效果求解；权限规则不能作为清除污点的依据 |
| 源到点统一查询与验证 | 没有通用 `trace_source_to_sink` 工具；已有专项测试不能代替源到点效果评测 |

这些是**尚未完成的内核能力，不是永久排除的产品方向**。
完整扫描编排、业务规则审批、模型运行和最终漏洞结论仍不属于本内核的职责。
这里的“未完成”也不意味着要求静态工具证明所有路径都能运行：
应先在明确的语言、框架和风险子集中完成自动候选追踪，并如实返回分析缺口。

三种状态必须分开：

```text
调用候选连接成功 ≠ 指定实参的传播已算清楚 ≠ 安全漏洞成立
指定路径走完     ≠ 所有调用者都已调查
未找到路径       ≠ 不存在漏洞
```

## 与原版 CBM、宿主平台怎样协作？

| 组件 | 定位 |
|---|---|
| 原版 CBM | 通用代码索引、结构导航、调用候选与变更影响 |
| CBM Sec | 源码观察、受限静态关系计算、框架语义与证据查询 |
| Agent 与宿主平台（如 Sulliu） | 按任务调查、补读源码、核对业务要求与反证，管理结论和报告 |

这是职责分工，不是当前已经接通的部署链。现有导航交接只把**位置与文件哈希**转换成本次源码的候选调用点，
不导入或证明外部图的全部关系。CBM Sec 内不调用模型，不再造一个 Agent 运行时。

## 构建与试用

在可信工具仓库中切换到功能分支，然后构建：

```sh
git fetch origin
git switch feat/security-facts-v0.1
git pull --ff-only origin feat/security-facts-v0.1

make -f Makefile.security
make -f Makefile.security test
build/security/cbm-security-facts --version
build/security/cbm-security-facts --capabilities
python3 security/demo_context.py --mcp build/security/cbm-security-mcp
```

构建需 C 编译器、Make 和 Python 3。产出两个独立 C 可执行文件：

| 文件 | 用途 |
|---|---|
| `build/security/cbm-security-facts` | 从标准输入读取单文件源码，输出语法事实；不是全仓库扫描命令 |
| `build/security/cbm-security-mcp` | 在启动时固定的源码包上提供只读查询；标准输入使用 MCP 消息 |

两个可执行文件运行时不依赖 Python；打包器和示例需要 Python 3/POSIX。
当前开发验证重点为 Linux x86_64，不沿用上游的全平台或性能宣传。
源码包准备与服务启动见 [SECURITY_MCP.md](SECURITY_MCP.md)，最新接口范围以本页链接的专题文档为准。
源码包包含完整源码，必须按原源码保护，不提交到公开仓库。

## 九个只读 MCP 工具

| 工具 | 作用 |
|---|---|
| `get_snapshot_info` | 核对快照、实际能力和解析计数 |
| `list_snapshot_files` | 分页列出已选文件，包括不支持分析的文件 |
| `query_security_facts` | 按类型、框架和直接所属声明筛选事实 |
| `get_security_evidence` | 按分析和事实编号读取证据 |
| `read_snapshot_source` | 按文件哈希和字节范围补读源码 |
| `resolve_code_location` | 将导航位置转换为候选事实，保留歧义 |
| `query_entry_points` | 枚举受支持的 Spring MVC 入口关系 |
| `inspect_operation_context` | 调查指定 Java 调用、参数关系和可选 MyBatis 映射 |
| `inspect_entry_security` | 调查指定 Spring 入口与显式配置范围的控制适用关系 |

一种入口优先的使用方式是：

```text
宿主准备固定文件集合与覆盖记录
    → get_snapshot_info
    → query_entry_points：取得入口与 call_query
    → query_security_facts：选择实际调用点
    → inspect_operation_context：先 summary，再按需 values/full
    → inspect_entry_security：需要时核对显式安全配置
    → Agent 继续调查未知项，宿主保存证据和结论
```

入口的方法编号不能当作调用点编号；`upstream_calls` 仍须另行查找并明确提供。
已有代码位置也可直接走 `resolve_code_location`。不要把上述步骤解释成已实现自动全仓源到点扫描。

## Skill 与 Hooks

核心技能在 [skills/cbm-sec-evidence/SKILL.md](skills/cbm-sec-evidence/SKILL.md)，
说明工具选择、分页、编号、分层读取和结果解释；框架差异放在按需参考中。
可选钩子只作会话提醒，默认关闭。两者必须从受信任的工具版本加载，不从被审计项目自动安装。

技能不代替静态算法，钩子不负责自动扫描或权限门禁。
源码和注释始终按不可信数据处理；只读声明不代替宿主的权限、隔离、预算和取消机制。
详见 [SECURITY_AGENT_GUIDANCE.md](SECURITY_AGENT_GUIDANCE.md)。

## 验证口径

专项测试使用真实解析器和 MCP 子进程；框架参考任务只运行仓库自带的受控样例。
Spring MVC 注册、MyBatis 模板处理、Spring Security 规则选择分别进行对照。
这些结果验证各自声明的分析子集，不代表完整业务漏洞检测效果。

测试数量、成功状态和产物须对应具体提交，以 [PR #1](https://github.com/Strugg1e/codebase-memory-mcp-sec/pull/1)
及相应任务日志为准。专项成功不等于整个仓库全绿。
没有真实 Sulliu/Codex 对照数据时，不声称召回率、准确率或 Token 收益。

## 文档导航

| 主题 | 文档 |
|---|---|
| 产品与宿主职责 | [产品定位](SECURITY_PRODUCT.md)、[接入与上下文视图](SECURITY_INTEGRATION.md) |
| 固定源码与基础事实 | [MCP 启动](SECURITY_MCP.md)、[语法事实](SECURITY_FACTS.md) |
| 框架和入口 | [框架范围](SECURITY_FRAMEWORKS.md)、[Spring MVC 入口](SECURITY_ENTRY_POINTS.md) |
| 参数与返回关系 | [显式多跳](SECURITY_FLOW.md)、[局部值流](SECURITY_LOCAL_FLOW.md)、[返回摘要](SECURITY_RETURN_SUMMARIES.md) |
| 数据与安全控制 | [操作上下文](SECURITY_OPERATIONS.md)、[MyBatis 模板](SECURITY_MYBATIS_TEMPLATES.md)、[Spring Security](SECURITY_ENTRY_SECURITY.md) |
| Agent 配套 | [技能与钩子](SECURITY_AGENT_GUIDANCE.md) |
| 历史发布 | [v0.6 预览说明](SECURITY_PREVIEW.md) |

专题文档可能保留首次引入时的版本描述；读取历史限制时，同时核对当前能力表与后续专题。

## 上游与许可

保留 [MIT 许可证](LICENSE) 和 [第三方声明](THIRD_PARTY.md)。
上游原 README 保存在 [UPSTREAM_README.md](UPSTREAM_README.md)，仅作来源参考，不能作为安全模块的能力声明。
当前复用基线为 `1db8bace03140f5793ff9205e5281732e77c2bea`，不自动宣称与最新上游同步。
产品定位已经独立，但代码来源与依赖关系不会因更名而消失。
