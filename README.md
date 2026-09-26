# CBM Sec

**面向审计 Agent 的框架结构提取、受限程序关系查询与源码证据回取工具。**

CBM Sec 帮助审计者找入口和数据操作，核对指定调用的参数关系，并回查固定源码中的证据。它不负责业务规则认定、假设调度或最终漏洞裁决，也不是完整 AI SAST 平台。

> **当前是未完成的预览整合分支。** 程序内部版本为 `0.15.0-preview.1`，注册十二个只读 MCP 工具；原始候选的新增专项和示例仍待核验；现已独立实现单操作离线证据交接，不代表原候选恢复。版本字符串不表示已发布。2026-09-21 检查时，`main` 仍为 `bec1cd1...` / `0.14.0-dev`，PR #5 尚未合并。[交付状态](docs/development/status.md)分别记录代码、验证和发布状态。历史 [v0.6 预览包](https://github.com/Strugg1e/codebase-memory-mcp-sec/releases/tag/cbm-sec-v0.6.0-preview.1) 不包含本次新增核心能力。

[快速开始](docs/getting-started.md) · [工具与能力](docs/tools.md) · [目录职责](docs/development/repository-layout.md) · [贡献指南](CONTRIBUTING.md) · [文档索引](docs/README.md)

## 三类用途

| 问题 | 工具提供的材料 |
|---|---|
| 查结构 | 固定文件清单、语法和框架声明、受支持的 Spring MVC 入口、普通 MyBatis 操作及未连接声明 |
| 查关系 | 选定 Java 实参的局部/返回关系、声明调用候选、安全配置关系及受限反向查询 |
| 回取证据 | 固定快照、文件哈希、准确源码位置、关系前提、未知项和原文 |

侦查主要使用结构材料；威胁建模和假设生成按需复用；对抗性验证按具体问题核对关系；报告回取源码证据。五阶段属于宿主，不是工具内的五套运行系统。源码足够时允许不调用 CBM Sec，工具是否支持不能成为假设准入门槛。

## 构建与已有回放

需要 C 编译器、Make 和 Python 3。下列命令检出当前整合分支，不是安装稳定版。开发验证主要面向 Linux x86_64，不沿用上游跨平台承诺。

```sh
git clone --branch release/prepare-cbm-sec-v0.15.0-preview.1 --single-branch \
  https://github.com/Strugg1e/codebase-memory-mcp-sec.git
cd codebase-memory-mcp-sec
make docs-check
make -f Makefile.security
build/security/cbm-security-facts --version
build/security/cbm-security-facts --capabilities
python3 security/demo_context.py --mcp build/security/cbm-security-mcp
python3 security/demo_trace.py --mcp build/security/cbm-security-mcp
python3 security/demo_flow.py --mcp build/security/cbm-security-mcp
```

示例使用受控源码，只运行分析器，不执行被审计项目。上面的既有回放不替代尚未同步的普通实参、资源与导出专项。检查未完成或失败时，不应合并或发布当前分支。

`make`、`make test`、`make docs-check` 和 `make help` 使用安全产品入口。两个程序是 `cbm-security-facts` 和 `cbm-security-mcp`。快照准备见[快速开始](docs/getting-started.md)。不要运行原版 `install.sh` 安装本工具，也不要把上游 npm/PyPI 包当作 CBM Sec。

## 支持范围与边界

| 领域 | 当前代码中的范围 |
|---|---|
| 语法事实 | Java、Python、JavaScript、TypeScript、TSX、Go；XML 用于 MyBatis |
| 框架声明 | 能力表列出的 Spring、Jakarta/Javax、MyBatis/JPA、Python/JavaScript/Go 框架的文档化写法；不证明实际部署激活 |
| Java 值流 | 受限局部复制、覆盖、表达式依赖、分支合并、同类辅助方法摘要和部分 String 返回模型 |
| 普通实参回溯 | 选定调用的一个实参；不要求先选漏洞规则或 Mapper；最多 16 个 Java 文件、四跳调用者 |
| 数据操作 | 普通 MyBatis 结构清单含参数化、常量、写操作和未连接声明，不默认运行局部值流 |
| 配置与专用规则 | 受限 Spring Security 规则选择；保留旧 MyBatis 文本替换回溯 |
| 输出与缓存 | full / summary / values 视图；同一固定源码进程中最后一条完整操作结果缓存 |

不是通用全仓污点扫描器。没有完整 Java 类型解析、通用运行时调用图、完整对象/数组内容传播、任意跨文件返回求解或净化证明。其他语言不自动具有 Java 的分析深度。源码引用真实不等于关系正确，关系存在不等于路径必然执行，到达形参不等于攻击者可控。

已独立实现[完整操作结果的离线交接](docs/reference/evidence-handoff.md)及受控回放；原始候选、新增专项与受控 Java 参考仍列在[待整合清单](docs/development/status.md)中。范围扫描、检查点恢复和历史 CFG/finally 实验不在本次交付范围。

## 按需使用

选择当前问题需要的入口、调用和实参。只需概览时取 summary，需要完整证据时按 full_request 展开；不要把所有工具串成固定流水线。首次操作仍进行完整计算，缓存是否减少重复工作应查看真实计数，而不是按输出视图推算。

零候选、不支持、预算停止、解析失败和关系被反证必须分开。保留未解析候选和未访问范围；工作队列结束不证明全仓完整。源码、注释与仓库说明始终是不可信数据。

[十二个工具与调用衔接](docs/tools.md) · [普通实参接口](docs/reference/argument-origins.md) · [Skill 与可选提醒](docs/reference/agent-guidance.md)

## 仓库与验证

`security/` 是工具实现，`skills/cbm-sec-evidence/` 是按需使用说明，`tests/security/` 是专项回归，`docs/` 是中文文档。`internal/cbm/`、`src/foundation/` 和 `vendored/` 保留复用依赖及来源；其余上游模块和安装器不是本产品默认入口。详见[目录职责](docs/development/repository-layout.md)。

完整安全专项使用 `make -f Makefile.security test`，文档使用 `make docs-check`。本地检查、远程 CI、框架参考及业务效果评测分别记录；不把历史测试或局部成功作为本次完整通过。见[验证说明](docs/development/testing.md)。

## 来源与许可

派生自 [DeusData/codebase-memory-mcp](https://github.com/DeusData/codebase-memory-mcp)，上游基线为 `1db8bace03140f5793ff9205e5281732e77c2bea`，不宣称已同步最新上游。遵循 [MIT 许可证](LICENSE)和[第三方声明](THIRD_PARTY.md)，保留[上游原文归档](docs/upstream/README.md)。上游性能和发行范围不构成本工具的承诺。
