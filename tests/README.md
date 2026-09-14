# 测试导航

`security/` 是 CBM Sec 专项回归，使用真实解析器和 MCP；少量故障注入只验证协议或恢复行为，不作为语义正确性的证据。

`spring-reference/`、`mybatis-reference/`、`spring-security-reference/`、`java-string-reference/` 是受控参考实验。它们的依赖和运行方式见各自 README，普通单元测试不会自动启动目标应用。

其他根层 C、Shell 测试及 `repro/` 主要来自原版 CBM。相关断言继续用于上游兼容区，不将其语言数、客户端数或发布宣传套到安全工具上。

从仓库根执行 `make test` 或 `make docs-check`。完整口径见[验证说明](../docs/development/testing.md)。
