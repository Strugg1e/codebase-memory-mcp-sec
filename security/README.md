# 安全分析模块

本目录是 CBM Sec 的产品实现；不等同于原版 `src/mcp/` 和持久化图流水线。

| 模块 | 职责 |
|---|---|
| `facts.*`、`parser.*`、`query.*` | 文档身份、语法事实、范围与分页查询 |
| `models.c`、`java_models.*` | 框架声明候选 |
| `entry_points.*`、`entry_security.*` | Spring 入口和明确配置的适用关系 |
| `operation.*`、`mybatis_template.*` | Java 调用上下文及 MyBatis 映射/模板 |
| `local_flow.*`、`java_string_models.*` | 局部值流、受限返回摘要及 String 模型 |
| `flow.*`、`auto_trace.*` | 显式路径核对与选定危险参数的自动回溯 |
| `agent_views.*` | 概览、参数及完整上下文视图 |
| `main.c`、`mcp.c` | 单文件命令行与固定快照协议服务 |
| `capabilities.*`、`build_id.py` | 产品能力和构建身份 |
| `pack_snapshot.py`、`demo_*.py` | 明确文件集合的打包与受控工具回放 |

从仓库根执行 `make test`。当前范围见[工具表](../docs/tools.md)，开发边界见[架构](../docs/architecture.md)。新增能力先复用已有事实与关系，不复制一套独立传播解释器。
