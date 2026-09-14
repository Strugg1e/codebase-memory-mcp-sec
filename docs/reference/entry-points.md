# 0.11：Spring MVC 入口关系

本版增加第八个只读 MCP 工具 `query_entry_points`。它在启动时已校验的源码包中，
将明确的 Spring 类级映射、方法映射、处理函数、参数与相关控制声明组织为入口候选。
不运行被审计项目，不证明 Bean 注册、过滤链、部署 URL、身份可信性或授权。
其他语言和此前 Java 值流的范围不因本工具而扩大。

## 查询

```json
{
  "snapshot_id": "get_snapshot_info 返回并与宿主核对的快照编号",
  "framework": "spring-mvc",
  "path_prefix": "src/main/java",
  "limit": 20
}
```

只有 snapshot_id 必填；当前 framework 仅支持 spring-mvc。path_prefix 是路径组件边界上的相对路径，
不接收绝对路径或上跳路径。handler 是方法名称的精确筛选；entry_id 可精确读取本版本的一条候选。
route_path 对已解析的路径作精确比较，不模拟 URL 请求匹配。未解析路径仍可能返回，标记
`filter_status=route_path_not_resolved`，不能将它当作已经匹配该 URL。

返回 entries、coverage 和 page。每条入口主要包含：

| 字段 | 内容 |
|---|---|
| entry_id | 绑定分析版本和方法事实的身份；只能结合响应中的 snapshot_id 使用 |
| handler / class_name | 方法与直接所属类名称，不是运行时分派证明 |
| handler_source / class_source | 固定源码哈希、UTF-8 字节范围、有限预览 |
| declared_paths / conditions | 支持子集中的路径与显式条件；未知字段为 null 或保留空候选集与 gaps |
| mapping_declarations | 类级、方法级原声明及其来源，不丢弃未归一化材料 |
| inputs | 形参、类型、位置、显式输入/身份/校验注解；隐式绑定保持未建模 |
| control_declarations | 类或方法上的已识别控制声明，不表示已生效 |
| other_annotations / gaps | 其他注解与未解析部分 |
| handler_anchor / call_query | 回取方法事实，或查询该方法直接所属调用点 |

`handler_anchor` 用于 get_security_evidence，**不能把其中的 fact_id 当作 call_id**。
使用 `call_query` 查询 query_security_facts，从结果选择实际调用，再进入 inspect_operation_context。
值关系调查继续使用 summary/values/full 视图，不新增扫描或验证流程。
所有编号与引用仅在固定源码和相应工具版本中有效。

## 有界枚举，不让模型搬运整仓

每页最多50条入口，最多访问16个范围内文件和2 MiB源码；默认20条入口。
每个文件最多256个入口、4 MiB序列化入口内容。每个声明最多64个注解、64个形参，
每个字符串条件最多16项、单项512字节缓冲，路径组合最多64项，处理预算200,000步。
原源码包、解析器与进程上限继续生效。
页面返回体另有约2 MiB的分批边界；单条较大入口不切断，可独占一页，但仍受文件级4 MiB限制。
这些是当前实现限制，不是性能保证。

游标绑定快照、构建身份、筛选条件、文件及文件内进度。续页保留原条件，可改变每页条数。
**没有返回入口的一页也可能有 next_cursor**，例如该页访问的是不支持的文件。
遵循游标直到为空；宿主保存每页 coverage。最后一页不能覆盖此前页的失败记录。
分页结束只表示选定范围在本分析子集中的枚举结束，不表示全仓库接口或安全控制完整。
未知语法、预算耗尽或文件分析失败都有记录，不变成“零风险”。

源码按文件顺序处理。复用现有单文件解析缓存，并保留对应语法树；同文件续页共享入口目录。
切换文件会淘汰缓存，不构建全仓持久化图。get_snapshot_info.entry_points 返回实际构建和命中计数。
没有跨请求的全部快照目录缓存；频繁不同文件查询仍有解析开销。

## Spring 支持子集

直接顶层普通类、明确导入或完整注解名称、明确类和方法声明、普通字面量路径及数组。
Controller/RestController 标记独立保存；没有标记的映射仍保留为未确认注册的候选。
不根据类级路径单独创建处理函数。多个方法共用同一路径不会被合并。

- 类级和方法级路径作有限组合，保留尾部斜线及多路径；双方空路径保留空串和根路径候选。
- RequestMapping 显式方法集合按 Spring 参考行为取并集，不误作交集。空集合不是默认 GET。
- 不展开框架隐式 HEAD/OPTIONS 行为，不证明某个请求实际匹配。
- params 和普通 headers 保留组合约束；方法级非空 consumes/produces 覆盖类级声明。
- headers 中的 Content-Type/Accept 涉及额外媒体条件转换，暂不归一化，保留原文和缺口。
- 多重映射、未知属性、path/value 冲突、配置占位符、常量表达式、转义字符串、复杂路径模式均保留缺口。
- 继承、接口、嵌套类、自定义组合注解、动态注册和外部配置不自动展开。未解析结构不按名称猜测。
- 权限与校验声明保留所属层级，不求值权限表达式，不证明执行顺序或对本入口的运行时生效。

conditions 的组合仅描述受支持声明关系。runtime_registration_verified 始终为 false，
security_control_effectiveness 与 authorization 始终为 not_evaluated，public_url 为 not_resolved。
合法源码、所列语言子集和框架语义范围都是前提；语法解析成功不代替编译器或框架验证。

## 验证

```sh
make -f Makefile.security
python3 tests/security/test_entry_points.py build/security/cbm-security-facts
```

新增72项真实解析器/MCP测试，覆盖关联、参数/控制归属、歧义、动态条件、预算、分页、缓存与精确引用。
另有固定 Spring 6.2.6 的独立注册对照，见 [测试说明](../../tests/spring-reference/README.md)。
普通专项测试不安装或运行框架；注册对照只执行仓库自带的固定测试应用，不启动 HTTP 服务或被审计项目。
运行结果应以当前提交日志为准，测试代码存在不代表已经执行。

开发核对资料：Spring 请求映射文档与6.2.6的 RequestMethodsRequestCondition、RequestMappingInfo。
https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-requestmapping.html
https://github.com/spring-projects/spring-framework/blob/v6.2.6/spring-webmvc/src/main/java/org/springframework/web/servlet/mvc/condition/RequestMethodsRequestCondition.java
