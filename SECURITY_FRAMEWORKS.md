# 0.10 开发版：框架声明与语言生态

> 历史范围说明。0.12 的 XML/注解模式、模板标记修正和静态引用扩展以 [SECURITY_MYBATIS_TEMPLATES.md](SECURITY_MYBATIS_TEMPLATES.md) 为准。

> 0.11 开发版补充：新增第八个只读工具 `query_entry_points`，以及配套工具使用技能和默认关闭的可选提醒钩子。见 [入口关系](SECURITY_ENTRY_POINTS.md) 与 [Agent 配套](SECURITY_AGENT_GUIDANCE.md)。以下旧版范围保留。

本轮扩展的是已支持语言的框架适配，不是增加完整语言分析器。
Java、Python、JavaScript、TypeScript、TSX、Go 的语法范围不变；
局部值流、返回摘要和操作上下文仍限于文档规定的 Java 子集。

所有模型都是明确导入、本地绑定和语法形态下的**声明候选**。
没有执行目标、安装框架、连接数据库或验证运行配置。
存在路由、安全注解或中间件，不等于入口已部署或防护已生效。

## 新增和扩展的能力

| 生态 | 本轮可识别的内容 | 不做的推断 |
|---|---|---|
| Java / JAX-RS | jakarta.ws.rs 与 javax.ws.rs 的显式 HTTP 注解、Path、输入绑定、Context | Path 单独出现不是 HTTP 路由；不展开子资源定位器 |
| Java / Spring Security | 调用前后权限与过滤注解、Secured、方法安全启用、AuthenticationPrincipal、CurrentSecurityContext | 身份上下文声明不自动成为可信输入；不求值权限表达式 |
| Java / Jakarta/Javax Security | RolesAllowed、PermitAll、DenyAll、DeclareRoles、RunAs | 不从注解存在推出容器启用策略或访问可达性 |
| Java / Bean Validation | Valid、NotNull、NotBlank、NotEmpty、Size、Min、Max、Pattern | 约束声明不等于校验已执行，不是任何风险类型的通用净化 |
| Java / MyBatis | Select/Insert/Update/Delete 原始表达式、对应 Provider、Param、Mapper | 不展开 SQL 字符串、动态脚本、Provider 返回值或把注解直接接入 XML 参数求解 |
| Java / Spring Data JPA | Query 的原始查询及 nativeQuery 配置、Modifying | 查询不一律是 SQL 或只读；不解析派生方法名、不证明数据库操作生效 |
| Python / FastAPI | include_router、WebSocket 注册、应用中间件、security 中的常见凭证方案 | 不跨文件拼接 URL、不证明认证；auto_error=False 仍只是声明参数 |
| Python / Flask | add_url_rule、register_blueprint、endpoint；应用和 Blueprint 写法 | endpoint 字符串不是处理函数；未指定 view_func 可以留空 |
| Python / Django REST framework | api_view、action、permission_classes、authentication_classes、throttle_classes | 不从 APIView/ViewSet 继承自动生成路由；不求值权限类或装饰器顺序 |
| JS/TS/TSX / Fastify | 显式本地实例、简写路由、直接对象路由、register、部分请求生命周期 addHook | 不展开插件闭包、跨文件注册或动态对象配置 |
| Go / chi v5 | NewRouter、方法路由、Method/MethodFunc、With、Use、Mount、Route/Group 声明 | 不展开 Route 回调中的路由，不追踪任意接口或别名 |
| Go / Echo v4 | New、方法路由、Add/Match、Group、Use、Engine.Pre | 路径、组前缀和中间件单独保留；不计算最终公开 URL |

之前的 Spring MVC、Django URL/装饰器、Express、NestJS、net/http、Gin 能力保留。
能力清单现在包含 18 个框架/规范分类；这不是 18 套完整分析引擎，也不是版本兼容性认证。
Go 新适配只识别明确的 `github.com/go-chi/chi/v5` 和 `github.com/labstack/echo/v4` 导入，
使用实际包名 chi/echo，而不是将模块末尾的 v5/v4 当成标识符。支持显式导入别名。

## 新增证据字段

框架声明仍位于语法事实的 `framework_model` 中，新增可选字段：

- `input_kind`：请求绑定种类，或身份/请求上下文候选。
- `control_phase`：声明语义中的处理阶段，不是已证明的执行顺序。
- `data_operation`：MyBatis 注解声明的 read/insert/update/delete，不声称解释了 SQL 的实际效果。
- `expressions`：有准确字节范围的原始表达式，例如 methods、prefix、router、options、sql、query、access_expression。
- `expression_details_truncated`：是否达到表达式槽位上限。

最多保存 8 个命名表达式，每个预览仍有 UTF-8 安全截断和原始位置。
`declaration_arguments` 保留声明的原参数列表，中间件、选项、类列表等不会只因只展示路径而丢失。
Java 操作上下文的 framework_declarations 也保留这些字段；summary/values/full 继续可用。
每个位置都可回到固定源码核对，字段不含模型生成的业务结论。

### 三个容易出错的例子

```python
app.add_url_rule('/orders', 'orders_endpoint', read_orders)
```

Flask 的第二个参数是 endpoint 名称，第三个才是 view_func。
也支持关键字参数；仅有 endpoint 时不捏造处理函数。

```go
e.GET("/orders", readOrders, auth, rateLimit)
```

Echo 的处理函数为第二个实参，后面的参数是路由级中间件，不能套用 Gin 的末尾处理函数惯例。

```javascript
app.route({ method: ['GET', 'POST'], url: '/orders', preHandler: auth, handler: read });
```

Fastify 的 method、url/path、handler 从直接对象成员抽取，同时保留整个 options。
对象含展开、计算属性、重复键或 getter/setter 时，不挑选某个值作为确定材料，保留原始调用及
`framework_model_gap`。`get('/x', optionsOrHandler)` 无法区分第二个表达式时，保留
handler_or_options 和缺口，而不是把配置对象误当成处理函数。

## 识别边界

Java 按完整注解名称或明确 import 精确匹配；不推测通配 import、自定义组合注解或外部类路径。
JAX-RS 的 Path 在类上表示前缀声明，在方法上表示资源路径声明；只有 HTTP 方法注解才标为路由声明。
继承的框架配置、Bean 扫描、AOP、服务部署、事务、运行时动态修改和实际权限不在本轮证明范围。

FastAPI/Flask 路由挂载只保存路由对象、前缀及依赖表达式，不根据当前单文件材料自动拼接全路由。
DRF action 只保存方法、detail 和 url_path 声明，没有声称该方法已被某个路由器注册。
Fastify 支持分开初始化以及 `const app = require('fastify')()`；require 被覆盖时取消对应模型。
复杂配置对象变量、跨函数实例传递和插件回调参数仍不是本地工厂绑定。

同名覆盖、仅类型导入、声明文件、解析错误、展开参数等不应被视为有效运行时框架模型。
不支持的写法仍返回原语法事实；无匹配记录不代表没有入口、风险或安全控制。

## 使用

```sh
make -f Makefile.security
make -f Makefile.security test
build/security/cbm-security-facts --capabilities
build/security/cbm-security-facts --path src/api.ts --framework fastify < /snapshot/src/api.ts
python3 tests/security/test_framework_ecosystems.py build/security/cbm-security-facts
```

MCP 仍为七个只读工具，不改必填输入。使用 query_security_facts 的 framework/role 筛选，
或者 resolve_code_location 定位具体声明，再按编号回取证据。
Jakarta 请求输入注解可供已有 Java 参数来源查询使用；其请求可控性、身份可信性和授权仍需调查。

测试使用真实语法解析器和 MCP 子进程，包含错误包名、同名覆盖、仅类型导入、动态配置、
参数位置、UTF-8 引用、分页、单条回取及 Java 操作视图。它不是框架运行时或漏洞效果评测。
是否通过以该提交的实际测试日志为准。没有修改 main、旧发布标签或宿主平台配置。

## 开发核对资料（2026-09-11）

下列公开资料用于核对 API 名称、参数位置及声明含义，分析工具运行时不联网。

- Jakarta REST 4.0：https://jakarta.ee/specifications/restful-ws/4.0/jakarta-restful-ws-spec-4.0.html
- Spring 方法安全：https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html
- MyBatis 注解：https://mybatis.org/mybatis-3/java-api.html
- Spring Data JPA：https://docs.spring.io/spring-data/jpa/reference/jpa/query-methods.html
- FastAPI APIRouter：https://fastapi.tiangolo.com/reference/apirouter/
- Flask 3.1 API：https://flask.palletsprojects.com/en/stable/api/
- Django REST framework：https://www.django-rest-framework.org/api-guide/views/
- Fastify 5.11 路由：https://fastify.dev/docs/latest/Reference/Routes/
- chi v5 API：https://pkg.go.dev/github.com/go-chi/chi/v5
- Echo v4 API：https://pkg.go.dev/github.com/labstack/echo/v4
