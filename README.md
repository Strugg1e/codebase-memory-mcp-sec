# CBM Sec

**面向安全审计 Agent 的只读程序分析与证据查询工具。**

本项目由 [codebase-memory-mcp](https://github.com/DeusData/codebase-memory-mcp) fork 而来。
复用其语法库与基础组件，在独立的 `security/` 模块中提供调用点证据、有限 Java 值流和操作上下文。
**不是完整 SAST 平台，不内置大模型或 Agent 循环，不直接判定漏洞。**

## 版本与入口

- 当前功能分支：`feat/security-facts-v0.1`，开发版本 `0.12.0-dev`。
- 已发布的独立预览版：[0.6.0 Preview 1](https://github.com/Strugg1e/codebase-memory-mcp-sec/releases/tag/cbm-sec-v0.6.0-preview.1)。该包不含后续开发能力。
- fork 的 `main` 尚未合入安全模块。请以实际分支、提交和可执行文件版本为准。
- 不使用原版 CBM 的安装脚本安装安全工具；原安装器不会自动安装这些独立可执行文件。

## 职责边界

| 组件 | 负责什么 | 不负责什么 |
|---|---|---|
| 原版 CBM | 结构索引、符号导航、调用候选与变更影响 | 本项目的安全关系求解与结论管理 |
| CBM Sec | 固定源码上的事实、位置解析、参数关系和有界证据查询 | 扫描编排、业务规则审批、完整污点分析与漏洞结论 |
| 宿主安全平台，如 Sulliu | 任务、模型与权限管理；调查、反证、业务上下文和报告 | 不把未知结果解释成安全 |

共用成熟的 Agent 运行时，按任务选择工具和上下文；无需为 CBM Sec 再造一个 Harness。
当前桥接的是**导航位置 → 本次源码调用点**，不是持久化 CBM 图的导入或全自动调用者发现。

## 真实能力范围

| 能力 | 当前范围 |
|---|---|
| 语法事实 | Java、Python、JavaScript、TypeScript、TSX、Go；调用点、参数、声明、导入等 |
| 框架语义 | Java/Jakarta、Spring/MyBatis/JPA、Python Web/DRF、Express/NestJS/Fastify、Go HTTP/Gin/chi/Echo 的文档化声明候选；见框架范围表 |
| 源码版本 | 启动时校验并固定明确选择的文件集合；不承诺全仓库覆盖 |
| Java 操作 | 局部语法、显式 Mapper/MyBatis XML 关联；不证明控制生效 |
| 值关系 | 受限 Java 局部复制、覆盖、表达式、分支及同类辅助方法返回摘要 |
| 多跳 | 明确选择且逐跳核对的上游调用，最多四跳；不是自动路径发现 |
| 导航交接 | 按文件哈希和行/字节范围解析候选，保留同一行多次调用与歧义 |
| Spring MVC 入口 | 类/方法/参数/控制声明关联；固定快照内有界分页，不证明部署或鉴权 |
| Agent 配套 | 一份工具使用技能，可选会话提醒钩子；不自动安装、不作为安全边界 |
| 上下文视图 | `full`、`summary`、`values`；精简视图可回取同一完整上下文 |

其他语言的语法支持不等于具有 Java 的值流深度。循环收敛、完整异常、堆/数组内容、跨文件返回摘要、净化证明和业务规则判定仍未实现。

## 构建与验证

从此功能分支或其固定提交的源码根目录执行：

```sh
make -f Makefile.security
make -f Makefile.security test
build/security/cbm-security-facts --version
build/security/cbm-security-facts --capabilities
python3 security/demo_context.py --mcp build/security/cbm-security-mcp
```

构建需 C 编译器、Make 和 Python 3。两个 C 可执行文件运行时不依赖 Python；打包器和示例需要 Python 3/POSIX。
当前开发验证重点是 Linux x86_64。没有沿用上游的全平台验证、语言数量、性能或 Token 节省宣传。
示例是标注测试源码上的真实协议回放，不是大模型、真实 CBM 索引或业务效果评测。

## Agent 使用路径

```text
宿主固定源码并记录覆盖范围
    → get_snapshot_info 获取实际能力
    → 原版导航或直接源码搜索取得相关位置
    → resolve_code_location 核对文件哈希并取得候选调用点
    → inspect_operation_context(view="summary")
    → 按需 values 或返回的 full_request
    → Agent 继续检查缺口，宿主保存结论
```

源代码和其注释始终是不可信数据。只读提示不代替操作系统权限隔离。
语法事实、可能依赖、运行时条件与最终安全结论分别表达；空结果不等于安全。

入口调查可改用 `query_entry_points` 获取 `call_query`，再选择实际调用点。当前为八个只读 MCP 工具。
技能从可信工具版本的 `skills/cbm-sec-evidence/` 装载；可选钩子默认关闭，不从被审计仓库自动安装。

## 文档

- [Spring MVC 入口关系和分页](SECURITY_ENTRY_POINTS.md)、[技能与钩子边界](SECURITY_AGENT_GUIDANCE.md)
- [产品边界与宿主职责](SECURITY_PRODUCT.md)
- [导航交接、上下文视图与运行配置](SECURITY_INTEGRATION.md)
- [固定快照与 MCP 启动](SECURITY_MCP.md)
- [语法与框架候选](SECURITY_FACTS.md)、[0.10 框架生态及限制](SECURITY_FRAMEWORKS.md)
- [Java/MyBatis 操作上下文](SECURITY_OPERATIONS.md)
- [显式多跳](SECURITY_FLOW.md)、[局部值流](SECURITY_LOCAL_FLOW.md)、[函数返回摘要](SECURITY_RETURN_SUMMARIES.md)
- [历史 v0.6 预览包](SECURITY_PREVIEW.md)

各历史文档保留其版本范围。当前能力以可执行文件的 `product_capabilities` 和对应提交测试结果为准。
完整结果默认不变；现有客户端无需修改。新客户端可显式选择精简视图。

## 上游与许可

上游原 README 字节保存在 [UPSTREAM_README.md](UPSTREAM_README.md)，仅作上游参考，不代表 CBM Sec 的能力或发布验证。
安全模块当前复用基线为 `1db8bace03140f5793ff9205e5281732e77c2bea`，不自动声称与最新上游同步。
保留 [MIT 许可证](LICENSE) 及 [第三方声明](THIRD_PARTY.md)。现阶段不拆仓库，不重写上游解析器；后续通过明确的源码和导航接口复用能力。

## 0.12：MyBatis 模板取证

XML 与有限注解查询共用模板标记提取，保留引号/注释内替换、条件、静态 include 和参数位置。
支持范围、兼容字段变化及对照测试见 [数据访问说明](SECURITY_MYBATIS_TEMPLATES.md)。不是完整SQL或漏洞引擎。
