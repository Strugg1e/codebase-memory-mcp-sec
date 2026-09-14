# CBM Sec

**为证据驱动的 AI 代码审计提供静态程序分析和可引用的代码上下文。**

CBM Sec 帮助审计 Agent 查找入口、理解安全配置、核对参数传播和数据操作。它负责回答“代码里有什么、这些值怎样关联、还缺哪些材料”；宿主平台负责提出威胁假设、组织独立验证和生成漏洞报告。

> **版本说明**：默认 `main` 是 CBM Sec 的开发入口，包含安全源码、中文文档和目录整理，程序版本仍为 `0.14.0-dev`。合入主分支不等于发布稳定版。历史 [v0.6 预览包](https://github.com/Strugg1e/codebase-memory-mcp-sec/releases/tag/cbm-sec-v0.6.0-preview.1) 不包含后续开发能力。请以实际提交、构建编号和能力表为准。

[快速开始](docs/getting-started.md) · [工具与能力](docs/tools.md) · [架构与目录](docs/development/repository-layout.md) · [贡献指南](CONTRIBUTING.md) · [文档索引](docs/README.md)

## 用它做什么

| 审计任务 | CBM Sec 提供的材料 |
|---|---|
| 项目侦查 | 源码文件、声明、调用现场；受支持的 Spring MVC 入口、输入绑定和相关控制声明 |
| 威胁建模与提出假设 | 有出处的程序和框架材料，供 Agent 解释资产、边界及业务要求；不把推断写成事实 |
| 假设验证 | 指定操作的参数来源、局部值流、返回值摘要、MyBatis 模板，以及 Spring Security 配置关系 |
| 自动路径调查 | 从选定的 MyBatis 文本替换参数出发，在给定范围中自动寻找上游请求来源 |
| 证据复核 | 固定源码版本、文件哈希、字节位置、关系前提和未完成项；可以回取原文 |

在你的双循环中，它同时服务**“找出合理且可验证的命题”**和**“寻找支持或推翻命题的证据”**。图查询和程序关系不是最终安全结论。

## 快速开始

需要 C 编译器、Make 和 Python 3。开发验证主要覆盖 Linux x86_64；不沿用上游的跨平台支持承诺。

```sh
git clone --branch main --single-branch \
  https://github.com/Strugg1e/codebase-memory-mcp-sec.git
cd codebase-memory-mcp-sec

make -f Makefile.security
build/security/cbm-security-facts --version
build/security/cbm-security-facts --capabilities

# 标注测试源码上的真实工具回放，不需要模型密钥。
python3 security/demo_context.py --mcp build/security/cbm-security-mcp
python3 security/demo_trace.py --mcp build/security/cbm-security-mcp
```

当前也提供 `make`、`make test`、`make docs-check` 和 `make help`。这些命令委托给现有安全构建，不会启动上游图服务或安装客户端配置。

两个程序分别是 `cbm-security-facts`（单文件事实查询）和 `cbm-security-mcp`（固定快照上的 MCP 服务）。快照准备和启动参数见[快速开始](docs/getting-started.md)。**不要运行原版 `install.sh` 来安装安全工具，也不要将原版 npm/PyPI 包当成 CBM Sec。**

## 已实现到哪里

| 领域 | 当前范围 |
|---|---|
| 语言解析 | Java、Python、JavaScript、TypeScript、TSX、Go；XML 用于 MyBatis 映射，不是通用事实语言 |
| 框架声明 | Spring、Jakarta/Javax、MyBatis/JPA；FastAPI、Flask、Django/DRF；Express、NestJS、Fastify；Go HTTP、Gin、chi、Echo 的文档化写法 |
| Java 值流 | 局部复制、覆盖、表达式依赖、分支合并；受限同类辅助方法返回摘要；受类型约束的部分 String 返回模型 |
| Spring MVC | 类和方法映射、处理函数、输入和控制声明；在选定快照中分页查询 |
| MyBatis | 明确 Mapper 的 XML/有限注解、参数绑定与文本替换、动态条件、同命名空间静态引用 |
| Spring Security | 明确配置范围内的链、规则顺序、忽略配置和有条件的匹配选择 |
| 自动回溯 | 一条内置 Spring/MyBatis 文本替换规则；选定危险调用后自动寻找调用者，最多四跳 |
| Agent 配套 | `summary` / `values` / `full` 视图；一份工具使用技能；默认关闭的可选会话提醒 |

**不是通用全仓污点扫描器。** 根调用、Mapper/映射和搜索范围仍需选择；没有通用净化证明、完整对象/数组传播、循环收敛或任意跨文件返回求解。其他语言不自动具有 Java 的分析深度。

危险点发现、检查点恢复和资源操作视图的本地候选不属于本分支已合入能力，见[交付状态](docs/development/status.md)。最新可执行能力以 `--capabilities` 和 `get_snapshot_info` 为准。

## Agent 如何使用

```text
宿主固定源码与分析范围
    → 查询能力和入口
    → 选择具体调用现场
    → 先读操作概览
    → 按需展开参数关系、安全配置或自动回溯
    → 回取证据，继续检查反面材料和未知项
    → 宿主形成限定范围内的安全结论
```

三个区别不能省略：**关系有候选不等于路径必然执行；配置存在不等于实际生效；没有找到路径不等于不存在漏洞。** 源码和注释始终按不可信数据读取。

[十个当前 MCP 工具及使用顺序](docs/tools.md)；[Skill 和 Hooks](docs/reference/agent-guidance.md)。工具技能从经过审核的本项目版本加载，不从被审计仓库自动安装。

## 仓库导航

```text
security/                 CBM Sec 分析核心、MCP、快照工具和示例
skills/cbm-sec-evidence/   核心工具技能与按需参考
hooks/                    可选会话提醒，默认关闭
tests/security/           安全模块回归测试
tests/*-reference/        受控框架/Java 参考实验
docs/                     中文使用、接口、架构与开发文档
docs/upstream/            上游原文、原站点和历史分发元数据
internal/cbm/             复用的语法运行时、语法库及上游抽取代码
src/foundation/           复用的哈希和随机数等基础组件
vendored/                 第三方组件及许可
```

`src/` 的其他模块、`graph-ui/`、`pkg/`、`Formula/`、`Makefile.cbm` 和安装器仍属于上游兼容区，不是本安全产品的默认入口。[完整目录职责与保留原因](docs/development/repository-layout.md)说明哪些能整理、哪些不能直接删除。

## 开发与验证

```sh
make docs-check   # 中文入口、链接、工具表、迁移记录和许可检查
make test         # 当前安全模块的真实解析器/MCP 回归
```

框架参考只运行仓库自带的受控样例，和普通专项测试分开记录。测试数量不等于漏洞召回率，也不代表真实业务环境已验证。详见[验证说明](docs/development/testing.md)。

## 来源与许可

本项目派生自 [DeusData/codebase-memory-mcp](https://github.com/DeusData/codebase-memory-mcp)，保留其语法库和基础代码，但安全产品使用独立的分析模块、构建入口和工具协议。当前上游基线为 `1db8bace03140f5793ff9205e5281732e77c2bea`，不宣称已同步最新上游。

遵循 [MIT 许可证](LICENSE)和[第三方声明](THIRD_PARTY.md)。[上游原文归档](docs/upstream/README.md)仅用于来源核对，不代表 CBM Sec 的性能、支持范围、维护者或发布承诺。
