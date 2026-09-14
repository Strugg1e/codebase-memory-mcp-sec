# 安全控制适用关系

当已定位Spring入口，需要调查请求级权限时使用 `inspect_entry_security`。
从入口响应取得path和entry_id，明确选入同一应用/环境的配置文件。
先省略具体请求阅读配置与缺口；有实际请求材料时，再提供request_method与request_path。
request_path是servletPath+pathInfo，不是外部URL。不要自行从模板随意造一个URL后宣称全部覆盖。

直接Ant构造只支持字面量和末尾双星。字符串重载默认保持未知；
只有宿主有证据时才设置string_matcher_semantics=ant-path，必须在交接中保留这是运行假设。
不要为得到确定结论，反复切换匹配假设试到“允许”或“拒绝”为止。

先查看coverage、assumptions和gaps，再阅读selection。
第一匹配链和链内第一规则不是所有规则的交集；未知前置匹配与相同顺序不能忽略。
忽略过滤与permitAll必须分开。请求级已认证、角色或权限要求不能替代订单所有权与租户成员检查。
方法级控制来自entry材料，未在本工具内求值或证明启用。
保留原源码位置与context_id，随后使用entry.call_query及现有操作工具继续调查参数和数据操作。
未选入配置、未知匹配器或没有匹配链，均不等于应用没有防护。
本工具不改变最终结论协议，不自动排除接口，不启动目标或新Agent。
