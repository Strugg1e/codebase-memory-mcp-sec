# CBM Sec

**面向证据驱动 AI 代码审计的静态程序分析内核与证据查询服务。**

CBM Sec 将源码中的入口、调用现场、参数关系、数据操作和安全配置组织成可引用的材料，帮助审计 Agent 提出具体问题、补充证据并检查反证。它不内置大模型，不替代宿主的调查流程，也不把一条代码路径直接判成漏洞。

> **先确认分支**：本仓库默认 `main` 的安全代码尚未合入。下表介绍的是安全开发线，而不是当前 `main` 目录已经具备的全部功能。请从 [安全开发分支](https://github.com/Strugg1e/codebase-memory-mcp-sec/tree/feat/security-facts-v0.1) 构建。

[安全开发分支](https://github.com/Strugg1e/codebase-memory-mcp-sec/tree/feat/security-facts-v0.1) · [开发说明](https://github.com/Strugg1e/codebase-memory-mcp-sec/blob/feat/security-facts-v0.1/README.md) · [功能 PR](https://github.com/Strugg1e/codebase-memory-mcp-sec/pull/1) · [历史预览包](https://github.com/Strugg1e/codebase-memory-mcp-sec/releases/tag/cbm-sec-v0.6.0-preview.1)

## 为什么做 CBM Sec

证据驱动的 AI SAST 有两项核心工作：找出有仓库依据、合理且可验证的威胁假设；寻找能够支持或推翻假设的证据。

CBM Sec 服务这两项工作。侦查时提供结构和框架材料，验证时计算受支持的程序关系。业务要求、攻击者条件和最终裁决仍由 Agent 与宿主平台组织，避免让每个会话从头搜索和拼接相同代码。

## 当前开发能力

| 方向 | 已有范围 |
|---|---|
| 多语言事实 | Java、Python、JavaScript、TypeScript、TSX、Go 的声明、调用点、参数、导入和准确位置 |
| 框架材料 | Spring、Jakarta/Javax、MyBatis/JPA，以及 Python、Node.js、Go 的部分 Web 框架声明 |
| Spring MVC 入口 | 受限的类与方法映射、处理函数、输入绑定、控制声明和快照内分页 |
| Java 值流 | 局部复制、覆盖、表达式依赖、分支合并、受限辅助方法摘要及部分 String 返回模型 |
| MyBatis 数据访问 | 明确 Mapper 的 XML/有限注解、参数绑定、文本替换、动态条件和参数关联 |
| Spring Security | 明确配置范围内的过滤链、规则顺序、忽略配置和有条件的选择结果 |
| 自动回溯 | 从选定 MyBatis 文本替换参数出发，在给定范围内自动寻找上游请求来源，最多四跳 |
| Agent 配套 | 固定源码包、只读 MCP、概览与完整证据视图、工具技能和默认关闭的可选提醒 |

开发线的程序版本为 `0.14.0-dev`；实际能力以对应提交的 `--capabilities` 为准。此前单独交付的范围发现、检查点恢复和资源操作本地候选，不自动计入远程已合入功能。历史 v0.6 Release 不包含这些后续开发能力。

**它还不是通用全仓污点扫描器。** 根调用、Mapper/映射和搜索范围仍需选择；没有通用净化证明、完整对象/数组传播、循环收敛或任意跨文件返回求解。支持某种语言解析，不等于具有与 Java 相同的分析深度。

## 构建和试用

需要 C 编译器、Make 和 Python 3；开发验证主要覆盖 Linux x86_64。先切换到安全开发分支：

```sh
git clone --branch feat/security-facts-v0.1 --single-branch \
  https://github.com/Strugg1e/codebase-memory-mcp-sec.git
cd codebase-memory-mcp-sec

make -f Makefile.security
build/security/cbm-security-facts --version
build/security/cbm-security-facts --capabilities

# 使用标注测试源码的真实工具回放，不需要模型密钥。
python3 security/demo_context.py --mcp build/security/cbm-security-mcp
python3 security/demo_trace.py --mcp build/security/cbm-security-mcp
```

生成 `cbm-security-facts` 和 `cbm-security-mcp` 两个程序。前者读取单文件源码，后者读取宿主固定的源码包并提供 MCP 查询。具体快照、工具和范围见开发分支说明。

**不要用根目录的原版 `install.sh`、`install.ps1`，或上游 npm/PyPI 包来安装 CBM Sec。** 它们属于尚未整理完成的上游兼容区。

## 与原版 CBM 的区别

| 组件 | 职责 |
|---|---|
| 原版 CBM | 通用代码索引、符号导航、调用候选与变更影响 |
| CBM Sec | 固定源码上的程序关系计算、框架取证与证据查询 |
| 宿主平台，如 Sulliu | 模型与任务管理、业务上下文、独立验证、报告与处理流程 |

安全开发线使用独立的 `security/`、`Makefile.security`、可执行文件和工具协议。原版代码图尚未直接导入安全服务，位置对齐也不等于调用关系已证明。

## 目录和文档说明

默认分支仍保留较多上游目录，这是源码整合尚未完成的状态，不代表安全产品仍使用全部原版组件。

安全代码主要在开发分支的 `security/`；专项测试在 `tests/security/`；工具技能在 `skills/cbm-sec-evidence/`；受控框架参考在 `tests/*-reference/`。语法运行时、语法库和必要基础组件仍从 `internal/cbm/`、`src/foundation/`、`vendored/` 复用。

本首页修订与完整功能 PR 分开，避免中文产品介绍一直等待全部实验代码合入。目录整理和候选功能需要各自检查、评审；本页不暗示已完成这些合并。

## 证据与安全边界

源码和注释属于不可信数据，不是 Agent 指令。源码包、查询结果和证据可能包含业务代码，应保存在私有产物目录。

调用关系候选、参数传播、安全控制适用性和漏洞成立是不同层次。未找到路径、不支持的语义和超出预算不能统一写成“没有漏洞”。不继承上游的性能、语言深度、平台覆盖、签名或安全扫描宣传。

## 来源与许可

本项目派生自 [DeusData/codebase-memory-mcp](https://github.com/DeusData/codebase-memory-mcp)，保留其技术来源与 [MIT 许可证](LICENSE)、[第三方声明](THIRD_PARTY.md)。

原首页按字节保存在 [上游 README 归档](docs/upstream/originals/README.md)，仅作历史来源核对，不作为 CBM Sec 的安装说明、维护者信息或能力承诺。
