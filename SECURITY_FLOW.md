# CBM Sec v0.6：有限多跳参数来源

本版为预览能力。真实构建与测试状态以对应提交的 CI 日志为准。
它不是完整污点引擎，也不是自动业务漏洞判定器。

## 使用范围

保持六个只读 MCP 工具，在 `inspect_operation_context` 中增加可选 `upstream_calls`。
按最近调用者在前排列，每项为 `path`、`analysis_id`、`call_id`，最多四项。
所有编号须从同一固定快照的 `query_security_facts` 取得，不能用函数名代替调用编号。

```text
请求形参 → 上游调用实参 → 业务方法形参 → Mapper 调用实参
                                     → 已有 Mapper/XML 映射候选
```

先选业务方法中的 Mapper 调用作为根，再给出调用该业务方法的上游调用点。
程序检查每跳的声明类型、唯一目标方法和参数位置，不直接相信所提供的路径。

```json
{
  "snapshot_id": "实际快照哈希",
  "path": "Service.java",
  "analysis_id": "Service的实际分析编号",
  "call_id": "Service内Mapper调用的实际编号",
  "mapper_path": "OrderMapper.java",
  "mapping_path": "OrderMapper.xml",
  "upstream_calls": [
    {"path":"Facade.java","analysis_id":"实际编号","call_id":"Service调用的实际编号"},
    {"path":"Controller.java","analysis_id":"实际编号","call_id":"Facade调用的实际编号"}
  ]
}
```

## 结果

`argument_flow.links` 保存声明类型下的调用候选及来源。
`argument_flow.paths` 按根实参保存逐层参数位置、最后来源及单独的停止原因。
`argument_flow.upstream_contexts` 保存每层局部材料；第 0 层是原始操作上下文。

`linked_candidate_hops` 仅表示调用候选连通，不等于所有参数都追踪成功。
`candidate_hops_followed` 表示该参数在这些候选前提下跟进的层数。
`selected_path_exhausted` 仅表示指定路径走完，不表示查完所有调用者。
原局部上下文的无传递式流分析说明仍适用于局部；跨层能力由 argument_flow 描述。

## 明确边界

仅跟进未被已覆盖写入或遮蔽影响的直接形参引用。换位按位置，不跨函数靠名字匹配。
别名、拼接、算术、调用返回值及字段内容停止为 expression_not_traced。
调用后发生的写入也可能保守停止。对象引用传递不代表对象字段未修改。

目标方法限顶层具体类。继承、接口派发、泛型、重载、变长参数及复杂接收者不猜测。
只支持明确声明类型的字段、形参或 this.field。原始 Java Unicode 转义不作语义证明。
所有路径保留 runtime_dispatch=not_verified、path_feasibility=not_evaluated、
object_contents=not_traced、taint_transformations=not_modeled、trust=not_established。
授权和业务规则没有在本工具内求值，不能用空路径排除漏洞。

## 资源与兼容性

每个输入最多 256 KiB，每棵树最多 50,000 节点，最多 64 条参数路径。
每次解析约 3 秒 CPU 预算；跨跳另查 5 秒累计预算，但当前跳可能先超出。
宿主仍须限制墙钟、内存和进程生命周期。整份操作 JSON 上限 4 MiB。
无多跳缓存；每个上游最多四次解析用于事实、局部上下文与两端连边核对。
操作计数反映真实工作。路径顺序、文件分析身份及调用点均参与 context_id。
不传 upstream_calls 时保持 v0.5 单跳行为。原语言和工具列表不变。

## 构建与验证

```sh
make -f Makefile.security
make -f Makefile.security test
```

新增 test_flow.py 使用真实 MCP 子进程与真实 Java 语法，不调用模型。
测试含参数换位、不同调用点、重写、别名缺口、声明类型、四跳上限及旧版本拒绝。
本版没有 Codex/Sulliu 实际会话或召回、Token、耗时收益评测。

## 后续静态内核

下一阶段统一 operation/flow 的程序表示，再加入局部值流、控制结构、函数摘要和
匹配调用/返回的按需求解。污点规则与身份/资源授权关系分开；授权不是清除污点。
没有完整分析能力的区域仍由 Agent 直接读源码调查，不将本工具变成扫描硬前置。
