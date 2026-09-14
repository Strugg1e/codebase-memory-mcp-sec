# CBM Sec 中文文档

这里是当前安全产品的文档入口。`reference/` 按主题保存接口说明，文内版本号表示该能力的引入时间，不表示每份文档都覆盖最新全集。当前工具集合以[工具表](tools.md)和可执行能力表为准。

| 目的 | 先读哪里 |
|---|---|
| 构建并跑通示例 | [快速开始](getting-started.md) |
| 选择和调用工具 | [工具与能力](tools.md) |
| 理解双循环中的职责 | [产品与架构](architecture.md) |
| 修改代码、定位目录 | [仓库结构](development/repository-layout.md)、[贡献指南](../CONTRIBUTING.md) |
| 核对验证和版本 | [测试方式](development/testing.md)、[交付状态](development/status.md) |
| 核对上游来源 | [上游归档](upstream/README.md) |

## 按主题查询

| 主题 | 详细说明 |
|---|---|
| 固定源码、MCP 与上下文视图 | [MCP](reference/mcp.md)、[接入](reference/integration.md)、[Agent 配套](reference/agent-guidance.md) |
| 语法和框架 | [语法事实](reference/facts.md)、[框架声明](reference/frameworks.md)、[入口](reference/entry-points.md) |
| Java 程序关系 | [操作上下文](reference/operations.md)、[显式多跳](reference/argument-flow.md)、[局部值流](reference/local-flow.md) |
| 返回值 | [辅助方法摘要](reference/return-summaries.md)、[String 模型](reference/string-models.md) |
| 数据访问和安全配置 | [MyBatis 模板](reference/mybatis-templates.md)、[Spring Security](reference/entry-security.md) |
| 自动回溯 | [源到危险参数](reference/source-sink.md) |
| 历史设计和发布 | [早期职责说明](reference/product-boundaries.md)、[v0.6 预览说明](reference/preview-v0.6.md) |

原根目录 `SECURITY_*.md` 已迁入 `docs/reference/`。精确对应关系见[迁移记录](development/migration.json)。根 `SECURITY.md` 现在只用于本工具的安全边界与报告流程。
