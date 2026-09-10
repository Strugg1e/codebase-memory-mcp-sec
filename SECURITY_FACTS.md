# 安全事实工具 v0.3

`cbm-security-facts` 是可选的纯 C 源码证据工具，不是完整 SAST，也不是完整安全语义图。
它复用本仓库固定的语法库，解析标准输入中的源码，不从聚合后的 CALLS 图恢复调用点。
原有 MCP、导航图、数据库、安装器和主构建流程不变。

本轮重点是框架绑定加固和按问题查询。没有增加新的语言，也没有引入大模型依赖。

## 语言与框架范围

| 语言 | 文件扩展名 | 框架声明模型 |
|---|---|---|
| Java | `.java` | Spring MVC 路由、输入注解；Spring Security 方法权限与启用声明 |
| Python | `.py`、`.pyi` | FastAPI、Flask/Blueprint、Django URL 与部分控制装饰器；`.pyi` 只保留语法事实 |
| JavaScript | `.js`、`.jsx`、`.mjs`、`.cjs` | Express 直接路由与中间件注册 |
| TypeScript | `.ts`、`.mts`、`.cts` | Express、NestJS；`.d.ts`、`.d.mts`、`.d.cts` 不生成运行时框架标注 |
| TSX | `.tsx` | 使用独立 TSX 语法，复用 TypeScript 模型 |
| Go | `.go` | `net/http`、ServeMux、Gin 直接路由、分组接收者与中间件 |

支持表示单文件、有限写法的语法抽取，不表示完整类型检查，也不保证覆盖所有框架版本。
未知扩展名返回错误，不偷偷改用其他语法。

## 框架标注的含义

原始事实始终为 `basis=syntax_observation`。可选 `framework_model` 的依据为
`import_and_syntax_candidate`。它是可复核的调查线索，不是可达性、授权或漏洞证明。

| 模型 | 支持的直接写法 | 明确不做 |
|---|---|---|
| Spring MVC | 明确导入或全限定名的请求映射及常见输入注解 | 组合注解、继承合并、完整路径拼接、控制器运行注册证明 |
| Spring Security | `PreAuthorize`、`PostAuthorize`、`PreFilter`、`PostFilter`、`EnableMethodSecurity` | 表达式求值、代理生效、全局过滤器链、实际授权判断 |
| FastAPI | 本地 FastAPI/APIRouter 构造，直接 HTTP 装饰器、`api_route`、`add_api_route`、依赖和输入声明 | 路由挂载、依赖执行、凭据验证、跨文件对象解析 |
| Flask | 本地 Flask/Blueprint 构造，直接路由及请求前后钩子 | Blueprint 注册、前缀合并、钩子顺序和效果 |
| Django | `path`/`re_path`，部分登录、权限、CSRF 装饰器 | `include` 展开、URLconf 生效、类视图派发 |
| Express | 明确 ES 模块或 CommonJS 导入，本地构造，直接 HTTP 方法和 `use` | 链式 `route(...).get(...)`、路由挂载合并、中间件执行证明 |
| NestJS | `@nestjs/common` 的控制器、路由、输入和控制声明 | 全局守卫、模块注册、组合装饰器、守卫内部逻辑 |
| Go Web | 明确 http 导入、本地 ServeMux 和 Gin 构造、直接路由与中间件 | 模式字符串求值、完整路由拼接、处理函数目标解析 |

标注保存导入、接收者构造、路径表达式和可用的处理函数表达式的位置。
路径不是最终部署地址；`Depends` 不是认证证明；`UseGuards` 不证明守卫生效。
`runtime_binding=not_verified` 和 `security_effect=not_evaluated` 始终保留。

## 本轮加固

- 局部 Python/CommonJS 导入不会泄漏到兄弟函数或外层作用域。
- Python 导入和 CommonJS 初始化须在被使用位置之前完成。
- 其他模块的明确同名导入也参与冲突处理，不再只登记已知框架。
- TypeScript 的整条及单个成员仅类型导入，不作为运行时装饰器来源。
- 接收者必须是直接成员；`app.database.get(...)` 不被当成 `app.get(...)`。
- 框架方法大小写和完整限定名须匹配，不能只按最后一个名称识别。
- 只把直接装饰器表达式当成装饰器调用，不把 `@wrap(app.get(...))` 内部调用直接归属于端点。
- FastAPI/Django 的常见关键字路径和处理函数参数可定位；缺失处理函数不生成完整注册候选。
- 展开参数、部分元组/解构/循环/删除造成的重绑定会保守处理。原始语法事实仍保留。
- 星号导入造成不明确绑定、声明专用文件、语法错误或模型预算不足时，不输出框架推断。

这些不是完整作用域或控制流分析。当前重名处理仍可能保守取消整个文件中相关标注，产生漏识别。
Python 条件分支中的导入按更窄范围处理，可能忽略合法的后续使用；类命名空间、闭包、动态
属性改写、反射、复杂别名、猴子补丁、未知 Go 包名仍需回查源码。未命中不表示不存在。

## 构建和测试

从仓库根目录执行，需要 C 编译器、make、完整源码和 Python 3。
Python 只用于构建指纹和测试，可执行工具没有 Python 运行时依赖。

```bash
make -f Makefile.security
make -f Makefile.security test
make -f Makefile.security test CC=clang BUILD=build/security-asan \
  CFLAGS='-O1 -g' SANITIZE='-fsanitize=address,undefined -fno-omit-frame-pointer'
```

`test` 构建真实语法并运行核心测试和 `tests/security/test_*.py` 中的全部端到端测试。
任何脚本失败都会使目标失败。没有录制响应、模拟解析器或模型调用。
专项 CI 运行 Clang 内存检查和 GCC 构建；通过不等于上游全量、DCO、CodeQL 和其他平台通过。
具体已执行结果以 PR 对应提交的日志为准。

## 按问题查询

`--path` 只作逻辑身份，不打开文件。Harness 应从固定只读快照读取源码后通过标准输入传入。

```bash
build/security/cbm-security-facts --capabilities

# 只返回 Express 的路由声明候选。
build/security/cbm-security-facts --path src/routes.ts \
  --framework express --role route_declaration --limit 20 < /snapshot/src/routes.ts

# 只返回调用点。
build/security/cbm-security-facts --path app/api.py \
  --kind call_site --limit 20 < /snapshot/app/api.py
```

可组合筛选项：`--kind`、`--framework`、`--role`、`--enclosing-id`。多个条件取交集，
值精确匹配、区分大小写。标签不支持正则或通配符；返回 `query.filters` 供调用者核对。

`--enclosing-id` 返回最近所属声明与该编号相同的事实。例如，先取得方法声明编号，再查询它
直接所属的注解、调用等。不会自动展开嵌套函数、跨文件调用、类级或全局安全控制。
找不到该编号时返回 `enclosing_not_found_in_extracted_scope`，不是空成功。

### 绑定条件的分页

推荐使用 `page.next_cursor`，并重复原查询的全部筛选条件。下面变量是占位值，需从上一页取值：

```bash
build/security/cbm-security-facts --path src/routes.ts \
  --framework express --role route_declaration \
  --cursor "$NEXT_CURSOR" --limit 20 < /snapshot/src/routes.ts
```

游标中的查询编号绑定单文件分析编号和所有筛选条件。源码、路径、语言、分析器版本或筛选
条件变化后返回 `query_mismatch`。可改变 `--limit`，不能在续页时删除或增加筛选条件。
有游标时无需另外传 `--expect-analysis`；传入时仍校验。

旧的无筛选 `--offset N --expect-analysis "$ANALYSIS_ID"` 继续可用。
带筛选的非首页必须使用游标，不能只有分析编号和偏移。`--offset` 与 `--cursor` 互斥。
游标不是签名、访问凭据或安全权限控制；它防止混用分析和查询条件，不阻止调用者主动选取偏移。

### 单条读取

```bash
build/security/cbm-security-facts --path app/api.py \
  --expect-analysis "$ANALYSIS_ID" --fact-id "$FACT_ID" < /snapshot/app/api.py
```

单条读取不能混用筛选、游标或非零偏移。未知编号返回明确错误。

## 字段与覆盖边界

| 字段 | 正确含义 |
|---|---|
| `analysis_id` | 单文件分析身份，不是已验证的仓库快照 |
| `query.id` | 分析身份和筛选条件的摘要；不含页面大小 |
| `page.extracted_total` | 本次抽取的所有事实数量，不受筛选影响 |
| `page.matched_total` | 已抽取记录中符合本次筛选的数量，不是实际接口或漏洞总数 |
| `page.offset` | 在匹配结果中的位置；旧单条读取保留原始记录位置 |
| `page.next_cursor` | 可继续读取时返回，否则为 null |
| `page.total_is_lower_bound` | 语法/遍历存在缺口，或框架筛选时有限规则处理未完成 |
| `call_site` | 独立调用位置；目标方法和运行可达性未证明 |
| `enclosing_id` | 最近受支持声明的编号，可能在另一页 |
| `argument_total` | 语法参数槽数量，不是展开后的实际参数数目 |
| `has_argument_expansion` | 存在 `*args`、`**kwargs`、`...args` 等，实际参数数量未知 |
| `arguments_truncated` | 超过 256 个参数位置；总数仍保留，但位置列表不完整 |
| `framework_analysis_complete` | 有限规则准备和遍历完成，不是框架覆盖率 |
| `framework_bindings_limited` | 绑定数量、长度或相关遍历达到保护上限 |
| `security_effect=not_evaluated` | 没有判断实际安全效果 |

即使 `total_is_lower_bound=false`，也只说明本次抽取/筛选没有已知预算或解析缺口。
不能据此认定框架建模完整。无匹配结果、模型停用和工具失败都不能转成“没有漏洞”。
筛选在抽取之后执行，减少的是返回上下文，不保证减少解析开销。

位置采用原始 UTF-8 字节偏移：起点包含、终点不包含。行号从 1 开始；`end_line` 是排他
终点所在行。预览最多 256 字节，不切断 UTF-8 字符；截断时须读取原始快照补齐。
筛选前验证事实位置，筛选不能掩盖损坏的证据记录。

## 资源、信任与集成

输入最多 1 MiB；解析约 3 秒 CPU 取消预算；每次主要遍历最多 200,000 节点；最多 20,000
条事实和 256 个模型绑定；每个调用最多返回 256 个参数，每页最多 200 条，输出最多 4 MiB。
模型准备使用多次有界遍历；绑定模式子树检查也有限额。输出超预算返回错误，不输出半截 JSON。

Harness 仍需限制墙钟时间、内存、输入等待和进程数，校验退出码及 JSON，并保存产物。
本工具不执行目标、不联网、不读取目标配置、不导入目标预生成图。源码指令不是系统指令。

缓存可使用 `analysis_id + query.id + 页面参数`。机械分页、批量文件处理和落盘由程序完成。
v0.3 改变分析器身份，旧分析编号和游标会失效。构建指纹覆盖实际参与构建的语法和模型源码，
包括未提交修改；它不是二进制签名，也不证明构建者可信。

**尚未实现**：持久化安全图、全仓快照管理、跨文件目标解析、值传播、完整路由组合、安全控制
生效证明、漏洞判定、原生 MCP 新工具和自动增量失效。Java Unicode 转义预处理也未建模。

## 扩展位置

`facts.*` 保存事实与输出；`query.c` 负责确定性筛选和游标身份；`parser.*` 负责语法抽取；
`models.c` 负责有限框架候选；`main.c` 处理命令行边界。新模型必须增加真实正例和反例。

规则设计参考：
[Python 名称绑定](https://docs.python.org/3.11/reference/executionmodel.html)、
[TypeScript 仅类型导入](https://www.typescriptlang.org/docs/handbook/release-notes/typescript-3-8.html)、
[Express 路由](https://expressjs.com/en/4x/guide/routing/)、
[Spring 方法安全](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)、
[FastAPI 依赖](https://fastapi.tiangolo.com/tutorial/dependencies/)、
[Flask 路由](https://flask.palletsprojects.com/en/stable/quickstart/)、
[Django URL](https://docs.djangoproject.com/en/dev/ref/urls/)、
[NestJS 控制器](https://docs.nestjs.com/controllers)、
[Gin 中间件](https://gin-gonic.com/en/docs/middleware/using-middleware/)。
