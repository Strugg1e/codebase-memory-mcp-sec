# MyBatis 操作取证

本说明对应 0.12 开发版。先检查服务能力中的 mybatis_template_schema；旧发行包没有这些能力。

先选取 Java 的实际调用点。默认 XML 模式同时提供 mapper_path 和 mapping_path。
只有调查明确的注解查询时，才使用 mapping_format=annotation、mapper_path，不提供 mapping_path。
这不是让模型猜框架会优先采用哪份映射；其他来源和运行配置仍需调查。

读取 mybatis.parameter_occurrences。#{...} 是参数映射候选，${...} 是文本替换；引号或 SQL 注释
不能用来排除模板标记。出现文本替换不等于漏洞成立，出现参数绑定也不等于整个操作安全。

argument_index 是根层操作的参数编号，用 arguments 中 index 相等的对象读取 local_value_flow，
不能把它当作精简视图数组中的下标。多跳结果按 argument_flow.local_value_paths 的 argument_index 关联。
聚焦视图可能没有其他参数的来源；需要时用 full_request 展开。未知来源不能填为可信。

root_argument_index 加 property_path 只说明对象根和属性路径；尚未证明该属性值来源，不可把对象
来源直接替代字段来源。OGNL、动态变量、转义表达式和未解析映射会保留缺口。

xml_conditions 是片段出现的条件材料，choose 分支属于同一选择组，但工具没有执行条件。
include_sites 记录每一次静态引用。相同片段被引用两次要保留两次，不只按源码位置去重。

template_analysis.segments 是按顺序收集的模板文本，不是运行时 SQL。不同分支的片段不能拼成一条
已执行查询。旧 sql_segments 是直接源材料；parameter_occurrences 自0.12改用模板阶段提取。
comparison_candidates 只是局部词法形态，不证明租户、对象授权、过滤效果或布尔蕴含。

把绑定、来源、条件、代码引用和未解决事项交给宿主。不要运行目标 Mapper、Provider、OGNL 或数据库。
