# 0.9：导航位置交接与按需上下文

> 0.11 开发版补充：新增第八个只读工具 `query_entry_points`，以及配套工具使用技能和默认关闭的可选提醒钩子。见 [入口关系](SECURITY_ENTRY_POINTS.md) 与 [Agent 配套](SECURITY_AGENT_GUIDANCE.md)。以下旧版范围保留。

这是可执行的查询接口，不是完整的 CBM/Sulliu 自动集成。
当前共七个只读 MCP 工具；原六个工具保留，新增 `resolve_code_location`。
没有新增模型、数据库、持久化图导入、全局客户端安装或扫描流程。

## 1. 宿主固定范围

使用 `SECURITY_MCP.md` 的源码打包器固定明确文件集合，启动受限的 MCP 进程。
用 `get_snapshot_info.product_capabilities` 读取产品能力、版本、实际接口范围及未实现项。
同一份能力对象也存在于 CLI `--capabilities.product_capabilities`；CLI 本身仍只做语法查询。
旧 `value_flow=false` 属于历史语法投影标志，不代表安全 MCP 完全没有有界值关系。
不要依赖根 README 的上游测试徽章或语言数量推断当前工具能力。

## 2. 把导航位置映射到本次调用点

原版 CBM 的符号位置（例如 file_path、start_line、end_line）由宿主规范化。
CBM 的压缩表格、qn 和不同版本输出不能直接当成下面的请求；本版不自动解析任意原始 CBM 响应。

```json
{
  "snapshot_id": "本次包哈希",
  "path": "src/OrderService.java",
  "sha256": "与导航构建所用源码核对过的完整文件哈希",
  "start_line": 12,
  "end_line": 30,
  "kind": "call_site",
  "limit": 20
}
```

`kind` 默认 call_site；也可用精确事实类别如 method_declaration。`name` 是精确名称，不是正则。
行范围为从 1 开始的闭区间。也可替换成从 0 开始的半开字节区间 start_byte/end_byte；二者不能混用，端点必须完整。
匹配方式是区间重叠，不是“选择第一个包含位置的节点”。所以嵌套调用或一行多次调用会返回多个候选。
默认不接收操作系统绝对路径；宿主必须先确认仓库根及相对位置，不能仅丢掉路径前缀。

返回 `candidates`、`coverage`、`page`、`analysis_id` 和以下状态：

| 状态 | 含义 |
|---|---|
| unique_candidate | 支持的语法查询中只得到一个候选，不证明目标函数或防护关系 |
| multiple_candidates | 多个不同现场；必须核对源码后选择 |
| no_candidate | 当前范围没有匹配记录，不等于没有调用/漏洞 |
| incomplete | 解析或遍历不完整；已返回候选也不能当作完整枚举 |

每个调用候选带 `operation_anchor`，可直接用于 inspect_operation_context 的 path/analysis_id/call_id。
不是每个语法调用都支持操作分析，Java 构造、lambda 等仍受原工具边界限制；其他语言只返回语法候选。
继续分页须保留相同 hash、范围、kind、name，使用 page.next_cursor；可变更每页条数。
游标绑定快照、分析版本和查询条件，不能跨范围继续。

**哈希必须来自可信固定源码清单。** 原版结果没有哈希时，宿主需验证其索引代次与源码清单。
仅把当前文件哈希附在旧索引位置上，无法证明旧索引仍有效。服务始终返回 external_graph_verified=false。
文件哈希不符时在解析前报错；不自动接受目标仓库自带的图或按同名节点拼证据。

## 3. 三个视图

```json
{
  "snapshot_id": "本次包哈希",
  "path": "src/OrderService.java",
  "analysis_id": "位置解析返回的分析编号",
  "call_id": "选择的调用编号",
  "view": "summary"
}
```

| view | 内容 | 使用场景 |
|---|---|---|
| full | 原始完整结果，不更改既有字段 | 保存产物、深入核查、兼容旧客户端 |
| summary | 新值关系、条件、Mapper材料、未知项；省略索引证据表和旧投影 | 首轮调查、决定下一步 |
| values | 新值关系及其作用域内证据表；可带 argument_index | 核对指定参数依赖 |

默认仍为 full。argument_index 从 0 开始，仅允许与 values 一起使用。
筛选只缩小根层参数及对应多跳路径；上游参数、控制与映射材料保留，防止误隐藏约束。
所有精简视图保留根层与上游 gaps、unknown_reasons、truncated、分派和路径限制。
省略的赋值/字段/退出语句数明确记录；不是说这些语句不存在。
summary 不保留指向已省略证据表的 evidence_ids。values 的证据编号仍只在各层各摘要内有效。
SQL 和动态 XML 条件不按参数筛掉。关系仍是可能依赖，不是可执行路径或安全结论。

精简结果带 `full_request`：

```text
full_request.tool
full_request.arguments
```

宿主可直接回取同一分析的完整输出。其中 expect_context 锁定 context_id；不匹配会报错。
视图和参数筛选不改变 context_id，也不改变底层分析结果。
没有新增操作缓存：重新展开会重新执行操作分析；因此不保证完整工作流更便宜。
缩小的是返回视图，不是解析/求解成本。小结果甚至可能因回取说明而更大。

## 4. 建议的阶段用法（不是权限强制器）

| 阶段 | 取哪些材料 | 不应做什么 |
|---|---|---|
| 准备 | 宿主程序建立快照、索引，核对版本与范围 | 让模型负责文件轮询和分页搬运 |
| 侦查 | 结构导航、位置候选、summary | 根据没有匹配记录宣告安全 |
| 威胁建模 | 中性操作上下文、版本化业务规则引用 | 从方法名自动生成可信规则 |
| 验证 | values、full、必要的源码补读 | 只看发现者结论、混用旧投影与新关系 |
| 报告 | 固定证据引用、反证和未知项 | 重新发现或自动升级工具材料为漏洞 |

宿主保存完整响应和实际工具错误。语义不支持时允许直接读同一快照源码；版本不一致时先修复交接，不偷偷换活目录。
缺省不把整个图或全部返回摘要放入每轮模型上下文。不同阶段共用分析器和成熟 Harness，而不是复制一套引擎。
不在被审计仓库中安装/信任 Agent 指令。业务规则和部署假设从宿主可信配置进入，保留来源与版本。

## 5. 可重复协议回放

```sh
make -f Makefile.security
python3 security/demo_context.py --mcp build/security/cbm-security-mcp
# 保留完整示例输出用于核对
python3 security/demo_context.py --mcp build/security/cbm-security-mcp --include-results
python3 tests/security/test_agent_integration.py build/security/cbm-security-facts
```

示例使用标注的 Java 测试源码和规范化导航位置，真实调用本工具，验证已知/未知关系和 full 回取一致。
报告每种视图的标准化 JSON UTF-8 字节数，不转换成 Token，不声称调用了原版 CBM 或真实模型。
后续真实工作流应分别记录：原始阅读、CBM辅助、CBM+Sec三组的同快照/同模型/同预算结果。
本轮不提供这项尚未执行的 A/B 结论，也没有修改 Sulliu 仓库或用户 Harness 配置。
