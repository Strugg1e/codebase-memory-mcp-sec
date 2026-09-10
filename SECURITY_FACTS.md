# 安全事实工具 v0.2

`cbm-security-facts` 是可选的纯 C 源码证据工具，不是完整 SAST，也不是完整安全语义图。
它复用本仓库固定的语法库，直接解析标准输入中的源码，不读取聚合后的 CALLS 图来恢复调用点。
原有 MCP、导航图、数据库、安装器和主构建流程不变。

## 语言与框架范围

| 语言 | 文件扩展名 | 本版框架模型 |
|---|---|---|
| Java | `.java` | Spring MVC 路由、输入注解；Spring Security 方法权限与启用声明 |
| Python | `.py`、`.pyi` | FastAPI、Flask/Blueprint、Django URL 与部分控制装饰器 |
| JavaScript | `.js`、`.jsx`、`.mjs`、`.cjs` | Express 直接路由与中间件注册 |
| TypeScript | `.ts`、`.mts`、`.cts` | Express；NestJS 控制器、路由、输入与控制声明 |
| TSX | `.tsx` | 同一 TypeScript 模型，使用独立 TSX 语法 |
| Go | `.go` | `net/http`、ServeMux、Gin 直接路由、分组接收者与中间件 |

语言能力是单文件语法抽取，不等于完整类型检查。框架能力是下面列出的有限写法，
不等于对该框架所有版本、所有扩展和部署方式的支持。未知扩展名返回错误，不偷偷按 Java 解析。

## 框架模型究竟做什么

原始事实仍是 `basis=syntax_observation`。命中模型后，额外附加 `framework_model`，
其依据为 `import_and_syntax_candidate`。这是一条带来源的框架候选，不会修改原始位置，
也不会变成“漏洞已确认”或“控制已生效”。

| 模型 | 支持的直接写法 | 明确不做 |
|---|---|---|
| Spring MVC | 明确导入或全限定名的 `RequestMapping`、`Get/Post/Put/Patch/DeleteMapping`，常见请求输入注解 | 自定义组合注解、接口继承合并、类与方法路径拼接、控制器运行注册证明 |
| Spring Security | `PreAuthorize`、`PostAuthorize`、`PreFilter`、`PostFilter`、`EnableMethodSecurity` | 权限表达式求值、代理生效、全局过滤器链、真实授权判断 |
| FastAPI | `FastAPI`/`APIRouter` 的本地构造绑定；HTTP 装饰器、`api_route`、`add_api_route`；`Depends`/`Security` 和常见输入声明 | 路由挂载及前缀展开、依赖实际执行、凭据验证、跨文件导入对象 |
| Flask | `Flask`/`Blueprint` 的本地构造绑定；`route`/HTTP 装饰器、`before_request`/`after_request` | Blueprint 注册和前缀展开、钩子执行顺序与实际效果 |
| Django | `django.urls.path`/`re_path`；`login_required`、`permission_required`、`csrf_exempt` | `include` 展开、URLconf 生效、类视图派发、装饰器执行证明 |
| Express | ES 模块默认/具名/命名空间导入，`require('express')`；本地 `express()`/`Router()`；直接 HTTP 方法和 `use` | `route(...).get(...)` 链式写法、路由挂载合并、中间件顺序和控制流证明 |
| NestJS | 从 `@nestjs/common` 明确导入的 `Controller`、HTTP 装饰器、`UseGuards/UseInterceptors/UsePipes`、常见请求参数装饰器 | 全局守卫、模块注册、组合装饰器、守卫内部逻辑 |
| Go Web | 明确导入的 `http.Handle/HandleFunc`、本地 ServeMux；Gin `New/Default`、本地 Group、HTTP 方法与 `Use` | Go 模式字符串中的方法解析、完整路由拼接、处理函数目标解析、全局中间件生效 |

模型支持上述明确导入的别名。只见到 `app.get` 或名为 `GetMapping` 的自定义注解，不能认定框架。
普通 `Depends` 表示依赖声明，不代表认证。`csrf_exempt` 表示控制豁免声明，不直接判定漏洞。

识别过程保留导入位置、接收者构造位置、路径表达式和可用的处理函数表达式。
Java/Python/NestJS 装饰器还可通过 `enclosing_id` 查找所属声明。路径是原始表达式，
不是完成拼接、配置替换和部署映射后的实际地址。默认方法与隐式 HEAD/OPTIONS 不展开。

同名导入、直接重复赋值、常见参数遮蔽会保守地取消相关模型。此策略可以少报，不会选择一个
看似合理的目标。动态属性改写、反射、复杂解构、猴子补丁等不在证明范围；
`runtime_binding=not_verified` 始终保留。解析有错误或模型准备超过预算时，停用框架推断，保留原始事实和缺口。

## 构建和测试

从仓库根目录执行，需要 C 编译器、make、完整的本仓库源码和 Python 3。
Python 只用于构建指纹和测试；可执行工具没有 Python 运行时依赖。不新增解析器包。

```bash
make -f Makefile.security
make -f Makefile.security test
make -f Makefile.security test CC=clang BUILD=build/security-asan \
  CFLAGS='-O1 -g' SANITIZE='-fsanitize=address,undefined -fno-omit-frame-pointer'
```

`test-core` 验证编号、来源、序列化和查询边界；`test` 还运行原有 Java 回归和新增多语言、框架正反例。
测试输入是真实源码，调用仓库内编译的真实解析器，不是录制输出或模拟解析结果。
独立 CI 在 `.github/workflows/security-facts.yml`，运行 Clang 内存检查和 GCC 构建。
专项检查通过不代表上游全量回归、CodeQL、DCO 或其他平台检查通过。

## 使用

`--path` 是逻辑路径，不会被工具打开。由 Harness 从固定只读快照读取源码后传入。

```bash
build/security/cbm-security-facts --capabilities

build/security/cbm-security-facts --path src/OrderController.java --limit 20 \
  < /snapshot/src/OrderController.java
build/security/cbm-security-facts --path app/api.py --limit 20 < /snapshot/app/api.py
build/security/cbm-security-facts --path src/routes.ts --limit 20 < /snapshot/src/routes.ts
build/security/cbm-security-facts --path internal/routes.go --limit 20 < /snapshot/internal/routes.go
```

返回 `analysis_id`、`source`、`facts`、`coverage` 和 `page`。下一页必须使用返回的 `next_offset`，
并带上上一页的分析编号。以下为占位示例，替换变量后执行：

```bash
build/security/cbm-security-facts --path app/api.py \
  --expect-analysis "$ANALYSIS_ID" --offset "$NEXT_OFFSET" --limit 20 < /snapshot/app/api.py
build/security/cbm-security-facts --path app/api.py \
  --expect-analysis "$ANALYSIS_ID" --fact-id "$FACT_ID" < /snapshot/app/api.py
```

非首屏及单条查询必须带 `--expect-analysis`。`--offset` 与 `--fact-id` 不可一起用。
默认 50 条、最多 200 条。分页只枚举本次已抽取记录，不能补齐遍历预算之外的源码。

同一源码、路径、语言和分析器源码版本生成同一编号。升级 v0.2 会使旧分析编号失效。
构建指纹覆盖全部实际参与构建的语法源码、扫描器与模型，包括未提交修改；
它不是二进制签名，也不证明构建者可信。构建目录另有编译参数标记，避免混用不同编译参数的对象文件。

## 输出字段

| 字段 | 正确含义 |
|---|---|
| `call_site` / `target_resolution=not_attempted` | 独立调用位置；未证明方法目标和可达性 |
| `enclosing_id` | 最近受支持声明的编号，可能在其他页；不是跨文件符号解析 |
| `argument_total` / `argument_count_basis=syntactic_slots` | 语法参数槽数量。Python 关键字参数保留整段表达式 |
| `has_argument_expansion` | 存在 `*args`、`**kwargs`、`...args` 等；实际运行参数数量未知 |
| `arguments_truncated` | 参数位置超过 256 个；原始总数仍保留，不能视为完整返回 |
| `framework_model.role` | 路由、输入、依赖、中间件或控制等声明类别 |
| `import_evidence` / `receiver_binding_evidence` | 支持本次模式识别的源码位置，不是运行绑定证明 |
| `path_expression` / `handler_expression` | 原始路径／处理函数表达式，尚未做求值或目标解析 |
| `security_effect=not_evaluated` | 没有判断实际安全效果 |
| `framework_analysis_complete` | 本次有限规则处理是否完成，不是框架覆盖率 |
| `framework_bindings_limited` | 模型符号表达到上限；模型推断被停用 |
| `parse_has_error` / `traversal_complete` | 语法与遍历状态，不是安全审计完成率 |

位置是原始 UTF-8 字节偏移：`start_byte` 包含，`end_byte` 不包含。行号从 1 开始。
`end_line` 是排他结束位置所在行。`text_prefix` 最多 256 字节，不切断 UTF-8 字符。
文本截断时按位置回到原始快照读取，不能拼接预览来伪造完整路径。

## 资源、信任与集成边界

输入最多 1 MiB；解析约 3 秒 CPU 取消预算；每次遍历最多 200,000 节点；
最多 20,000 条事实、256 个模型绑定；每个调用最多返回 256 个参数；JSON 输出最多 4 MiB。
框架准备最多三次有界遍历。参数采用顺序游标遍历，避免逐项重复查找巨大参数列表。
输出超预算返回错误，不输出半截 JSON；可以减少页面条数再试。

Harness 仍需限制墙钟时间、内存、输入等待和进程数，并检查退出码和 JSON 完整性。
工具不执行目标、不联网、不读取目标配置或预生成图。源码和注解中的指令始终是不可信数据。

缓存键可用 `analysis_id + 查询参数`；仓库、提交与应用归属由外层快照清单负责。
批量遍历、分页、缓存和落盘由普通程序完成，不要求模型参与机械循环。
失败、不支持、空结果、预算缺口均不能转为“没有漏洞”。

**仍未实现**：持久化安全图、全仓库快照管理、跨文件目标解析、污点／值传播、
框架安全效果证明、漏洞判定、原生 MCP 新工具、自动增量失效。
Java Unicode 转义预处理、框架版本条件和动态绑定等仍需另行调查。

## 继续开发

- `security/facts.*`：通用事实、来源、编号与输出。
- `security/parser.*`：统一语法遍历、语言选择、调用点和参数抽取。
- `security/models.c`：有界导入与本地绑定、框架声明模型。
- `security/main.c`：命令行与标准输入输出边界。
- `tests/security/test_multilang.py`：新增模型必须配对加入正例与同名／别名／遮蔽反例。

框架模型参考（用于规则设计，不是运行时依赖）：
[Spring 方法安全](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)、
[FastAPI 依赖](https://fastapi.tiangolo.com/tutorial/dependencies/)、
[Flask 路由](https://flask.palletsprojects.com/en/stable/quickstart/)、
[Django URL](https://docs.djangoproject.com/en/dev/ref/urls/)、
[Express 中间件](https://expressjs.com/en/guide/using-middleware/)、
[NestJS 控制器](https://docs.nestjs.com/controllers)、
[Gin 中间件](https://gin-gonic.com/en/docs/middleware/using-middleware/)。
