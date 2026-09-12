# 自动源到参数候选取证（0.14）

先核对能力目录中的规则 `spring-mybatis-text-substitution`。
选择固定源码中正确的Java Mapper调用，以及同一应用内的scope_paths、Mapper和映射。
调用trace_source_to_sink，不填写upstream_calls；工具会在预算内寻找并核对调用者。
这是选定危险调用的反向分析，不是全仓危险点发现。

先看status、paths、frontiers、coverage、gaps与truncated，再展开contexts。
路径步骤按sink_to_source排列；每步证据编号只属于context_index指向的局部上下文。
同一模板的多个标记、同一方法的多次调用、已知与未知来源不要合并丢失。

Source是明确映射方法中的标量请求形参候选。DTO字段和Principal不能凭名称代替。
Sink是当前规则选中的MyBatis文本替换位置，不是所有数据库操作。
整数等绑定约束可能改变SQL注入可利用性；路径命中不是漏洞确认。
XML配置属性阶段、动态条件、转义前提必须随候选保留。

未找到来源、绑定未解析、预算中断和常量覆盖是不同情况；都不能生成全应用安全结论。
不要把sanitize函数名、权限注解或登录规则视作净化证明。
不支持的调用者和字段返回源码继续调查，不能要求模型虚构一条完整链。
完整接口与范围见SECURITY_SOURCE_SINK.md。
