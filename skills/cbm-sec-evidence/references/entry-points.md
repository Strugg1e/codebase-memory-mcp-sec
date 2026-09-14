# Spring 入口查询

输入必须使用宿主已固定的 snapshot_id。`path_prefix` 匹配路径组成部分，例如 src 匹配 src/C.java，不匹配 src-other/C.java。
`handler`、`route_path`、`entry_id` 都是精确筛选；route_path 比较声明路径，不进行 HTTP 请求匹配。

```json
{"snapshot_id":"替换为实际快照哈希","path_prefix":"src","limit":10}
```

调用 `query_entry_points`，后续页保持所有筛选条件，只增加返回的 `page.next_cursor`。可调整 limit。
每页最多访问16个范围内文件或2 MiB源码。空页可能仍有next_cursor。coverage只描述当前页，应由宿主累计。
入口按照处理方法保存，declared_paths中保留该方法的多个映射组合；不同方法即使路径相同，也不会去重。

支持直接Spring MVC映射、字面量路径与数组、类/方法关系及直接参数注解。
路径占位符、复杂模式、重复映射、继承、自定义组合注解、注册与配置激活并未被完整求解。
空methods表示没有显式请求方法限制，不是默认GET；HEAD/OPTIONS并未展开。
params/headers保留约束材料；媒体类型声明遵循方法级覆盖；特殊媒体类型请求头无法归一化时保留缺口。

`handler_anchor`用于get_security_evidence。`call_query`用于取得处理方法直接包含的调用，随后选择真实call_id。
class/method control_declarations不等于过滤链覆盖；参数校验和身份注解不自动证明可信。
