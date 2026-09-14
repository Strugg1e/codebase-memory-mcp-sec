# v0.13：Spring Security 控制适用关系

本版新增第九个只读 MCP 工具 `inspect_entry_security`。
输入来自已固定源码中的一个 Spring 入口和明确选择的配置文件。
输出是配置材料，以及**在明确前提下**的过滤链/规则选择，不是登录、授权或漏洞结论。
生产工具不加载 Spring，不执行配置方法、表达式、自定义匹配器或目标代码。

## 使用

先用 `query_entry_points` 取得入口的 `path` 和 `entry_id`，再调用：

```json
{
  "snapshot_id": "本次服务返回并与宿主核对的快照编号",
  "path": "src/OrderController.java",
  "entry_id": "本次入口编号",
  "config_paths": ["src/SecurityConfig.java"],
  "request_method": "GET",
  "request_path": "/api/orders/123"
}
```

`request_method` 和 `request_path` 必须一起提供，也可以一起省略。
省略时只返回声明、控制和未解析项，不替入口猜一个请求。
路径表示应用内部的 `servletPath + pathInfo`，不是浏览器完整 URL。
不会移除查询串、解码百分号、归一化分号或路径跳转；不支持的形式返回未知。
当前请求和入口的实际路由关系始终未验证，不证明入口所有路径都受同一规则覆盖。

配置必须属于同一应用/环境。工具只分析 `config_paths`，不会自动寻找其他文件。
目录内可能还有未选入的配置、网关或过滤器；`no_matching_chain_in_selected_scope`
不能用于宣布整个应用无防护。

## 匹配器边界

支持带明确导入或完整名称的 `new AntPathRequestMatcher("/path")`，
以及第二个参数为 HTTP 方法字符串或 null 的构造形式。只计算大小写敏感的完整字面量路径
和末尾 `/**`；后者包含基础路径本身。复杂星号、正则、变量模式和三/四参数构造保留未知。
不把静态工厂、任意对象、动态方法枚举或错误导入按名称当作已解析匹配器。

`securityMatcher("/api/**")` 和 `requestMatchers("/api/x")` 由框架选择具体匹配器。
默认 `string_matcher_semantics=unresolved`，这些路径不作确定匹配。
宿主只有掌握相应环境依据时，才可以显式传入 `string_matcher_semantics="ant-path"`。
这是**未独立验证的宿主假设**，不是工具自动探测出的运行配置；结果明确记录该前提。
不支持的匹配语义不能被这项设置强制变成确定匹配。

## 支持的配置子集

- 同一文件内的直接顶层普通类、明确导入/完整类型名。
- `@Bean SecurityFilterChain` 方法、唯一的 HttpSecurity 形参。
- 直线调用与 `return http.build()`，包括直接返回整条调用表达式。
- 方法 `@Order` 的普通十进制常量。无声明时，在不存在其他排序来源的前提下按最低优先级处理。
  不按文件名排序打破相同顺序；复杂顺序和重复工厂名称保留歧义。
- `securityMatcher` 及单个 `authorizeHttpRequests` 直接 lambda。
- `requestMatchers`、`anyRequest` 与 `permitAll`、`denyAll`、`authenticated`、
  `hasRole`、`hasAuthority`、`hasAnyRole`、`hasAnyAuthority` 的有限直接写法。
- 直接 `WebSecurityCustomizer` 返回 lambda 的 `web.ignoring().requestMatchers(...)`。
- 常见其他配置的明确 `Customizer.withDefaults()` 或单一 `disable()` lambda，
  只保留源码，不解释 CSRF、登录、响应头等实际效果。自定义回调/过滤器可能改写请求，保留缺口。

分支、循环、构建器别名或改写、辅助函数生成配置、继承/接口、泛型配置、
条件装配和自定义注解、Bean 选项、多个授权配置器、早退、自定义授权器等不做完整求解。
匹配材料仍可保留，但未解析内容不得被跳过后输出一个虚假的唯一答案。
`hasRole` 的输出保留声明的角色文本，不替用户求值角色层级、角色前缀或业务对象权限。
旧式 WebSecurityConfigurerAdapter、XML 安全配置、MVC/PathPattern/正则匹配器不在本版范围。

## 输出与解释

| 字段 | 含义 |
|---|---|
| `entry` | 原入口、控制声明和可回取的方法/调用查询，保持快照身份 |
| `configurations` | 每个工厂的原始位置、导入依据、顺序、链匹配器、规则列表与缺口 |
| `coverage` | 所选配置文件的哈希和分析状态，不是全应用覆盖 |
| `selection.trace` | 所选范围中每个链/忽略配置的匹配状态 |
| `selection.candidate_chain_ids` | 在已知顺序约束下仍可能首先被选中的链 |
| `selection.rule_selection` | 已选链内部的候选规则及其要求，或未完成原因 |
| `assumptions` | 工厂注册、完整配置范围、没有外部改写等适用前提 |
| `context_id` | 绑定快照、工具版本、入口、配置内容、请求及匹配假设的身份 |

链按顺序选择第一条匹配者，链内同样选择第一项匹配规则，不将后续要求叠加。
前面有未知匹配器时，后面的规则仍可作为候选，但不能成为确定唯一结果。
已知第一项匹配后，单纯较晚的未知匹配器不会反过来改变它；未解析排序仍会阻止唯一选择。

`ignored_in_selected_configuration` 与 `permitAll` 不同。前者表示在上述前提下，
框架忽略列表可选择空过滤链；后者只是某条链中的请求授权要求，不跳过整条过滤链。
缺少最后的 anyRequest 时，已完整解析的授权配置器可返回其默认拒绝状态，
但这不是对其他过滤器、运行部署或整个应用的结论。

所有结果保持 `authorization_verdict=not_evaluated`、
`runtime_registration_verified=false`、`security_control_effectiveness_verified=false`。
它们说明本查询没有评估这些层次；不表示工具计算出的受限关系毫无价值。

## 预算和缓存

一次最多16个配置文件，每个256 KiB，总计2 MiB。最多64个工厂、每工厂32条规则、
每个匹配器8个选项，字符串缓冲512字节，总处理预算200,000步，输出上限4 MiB。
超出边界明确报错或保存不完整状态。UTF-8源码位置仍可回到固定快照核对。
配置按路径规范排序仅用于稳定输出，不决定Bean优先级。
入口解析复用原有单文件缓存；配置每次重新解析，不新增永久状态或缓存数据库。
`get_snapshot_info.entry_security` 记录实际请求与配置解析尝试次数。
宿主仍须提供进程级内存、执行时间和取消限制。

## 验证

```sh
make -f Makefile.security
make -f Makefile.security test
python3 tests/security/test_entry_security.py build/security/cbm-security-facts
```

专项用例使用真实解析器/MCP，另有固定 Spring Security 6.5.0 的框架对照：
`tests/spring-security-reference/`。框架只在受控测试中运行，无HTTP监听、数据库或任意目标加载。
测试存在不等于已执行；以对应提交的真实日志为准。不声称真实业务召回率或模型使用收益。

开发依据：Spring Security 6.5 文档及6.5.0源码中的 HttpSecurity、
AuthorizeHttpRequestsConfigurer、RequestMatcherDelegatingAuthorizationManager、FilterChainProxy。
https://docs.spring.io/spring-security/reference/6.5/servlet/architecture.html
https://docs.spring.io/spring-security/reference/6.5/servlet/authorization/authorize-http-requests.html
https://docs.spring.io/spring-security/reference/6.5/servlet/configuration/java.html
