# 0.12 开发版：MyBatis 模板与参数取证

本版扩展既有 inspect_operation_context，不增加 MCP 工具或生产目标执行能力。
目标是统一 XML 和有限注解查询的模板材料，并将参数位置连接到现有 Java 来源查询。
它不生成漏洞结论，不运行数据库，也不求值任意 OGNL 或 Provider。

## 1. 输入和兼容

默认 mapping_format=xml，继续要求 mapper_path 和 mapping_path 同时提供。
不调查映射时可同时省略两者，原有 Java 操作查询不变。

注解查询必须明确提供 mapping_format=annotation 和 mapper_path，并省略 mapping_path。
默认模式不变，不根据文件内容自动决定 XML 和注解的优先级。
两个模式均要求固定快照中的 Java 调用点及显式可关联的 Mapper 接口；既有接收者、重载、
形参位置、@Param、改写与同名遮蔽检查继续生效。省略的其他映射来源和运行注册状态不被证明。

```json
{
  "snapshot_id": "真实快照编号",
  "path": "src/OrderService.java",
  "analysis_id": "真实文件分析编号",
  "call_id": "真实调用事实编号",
  "mapper_path": "src/OrderMapper.java",
  "mapping_format": "annotation",
  "view": "summary"
}
```

注解支持明确导入或全限定的 Select/Insert/Update/Delete，纯字符串字面量及字面量数组。
注解的原始查询表达式保留。转义、文本块、常量拼接、脚本和任意 Provider 不执行、不猜解码。
未知注解属性、数据库变体、自定义 Lang、多重 SQL 注解和混合表达式保留未知或不完整结果。
不能把一份注解文件的候选命中解释为运行时真正选择了此映射。

## 2. 模板阶段与 SQL 结构分开

MyBatis 先处理模板标记，SQL 引号和 SQL 注释不阻止其中的参数/替换标记被模板处理。
本版修复了旧词法分析会漏记引号和 SQL 注释内标记的问题，例如 WHERE name='${name}'。
XML 注释不是 SQL 文本，不纳入此列表。

- #{name}：parameter_marker，参数映射候选。
- ${name}：text_substitution_marker，文本替换。
- 转义起始标记：记录 escaped_markers 及 effect，不能将它理解为“不会替换”。
- XML 的单个 `\${name}`：前置 PropertyParser 可先移除反斜杠，后续仍发生文本替换；保留此候选。
- XML 多重反斜杠：保留标记与 preprocessing_not_resolved，不建立确定的参数关联。
- `\#{name}` 在当前标记阶段仍按转义处理；不把 XML 美元标记的处理套给井号标记。
- 未闭合、跨片段、嵌套或转义结束符：保留缺口；不执行表达式或后续模板阶段。
- 文本替换可能改变 SQL 及后续参数标记，工具不假装枚举了替换结果。

XML 属性阶段可能先用运行配置替换 `${...}`。配置未提供时，参数关联附带
`parameter_binding_assumption=marker_survives_configuration_property_phase`，不能将该关联当作
已证明的运行时来源。转义处理始终保留原始字节，不伪造已归一化文本的位置。

`mybatis.template_analysis` 的结构版本是 cbm.mybatis-template.v1，包含有序 segments、
parameter_occurrences、escaped_markers、gaps、input_incomplete 和 truncated。
`mybatis.parameter_occurrences` 是同一列表的兼容投影，自0.12起包含引号和SQL注释内标记。
旧测试中排除这些标记的断言已按框架行为修正，而不是将失败测试跳过。

每个标记保留原始源码路径、哈希、UTF-8字节位置和受限预览。注解字面量对应去掉外层引号的
原始字节，不伪造生成SQL的位置。片段列表是模板材料，不是已经选定分支后生成的SQL。

## 3. 参数来源

明确的简单 @Param 名称可以关联到根层操作 argument_index，以及 value_origin_ref。
通过 arguments 中的 index 查找 local_value_flow；精简数组不能按原编号直接索引。
上游来源仍使用原有显式路径及 argument_flow.local_value_paths。本版不自动发现调用者。

`#{query.tenantId}` 保留 root_argument_index 和 property_path；不提供直接标量 argument_index，
不将对象整体来源等同于属性来源。索引访问、函数调用、任意表达式和保留上下文名称不求值。
缺少 @Param、不明确的别名及动态作用域不会被猜成某个形参。

## 4. XML 条件和静态引用

if/when 的原始 test 与片段关联；otherwise 记录无前置 when 命中的分支含义，并带同组 choose
的位置。工具不判断这些条件是否成立，不把多个分支当成同时执行的路径。

静态 include 限于同一 XML 命名空间中唯一的 sql 片段，可以使用本地或本命名空间限定 refid。
每次展开保留片段位置和 include_sites，重复引用不混为一个现场。支持受限嵌套。
带 property、动态 refid、跨文件引用、重复ID、数据库变体、缺失引用、循环及深度限制有明确缺口。

foreach 中的标记保留，但不将循环变量关联到外层同名参数。bind 或无法解释的模板部分会保守
取消相关位置绑定。XML 实体不解析，DTD不加载，不访问网络/文件系统。
where/trim/set 只作为模板结构材料；不输出已经执行了前缀删减或布尔判断的结论。

## 5. 资源材料

XML与注解使用同一份模板文本进入有限SQL词法分析。可得到首个操作词、明确领先表名，以及
单个文本片段中的 列=参数 候选。SET 下标为写入赋值候选，其他位置保留比较形态。
comparison_candidates 通过 template_occurrence_index 关联标记；guaranteed_scope 始终为false。

这是单片段词法材料，不是完整 SQL AST、表集合、字段语义或布尔蕴含分析。跨片段表名、CTE、
复杂子查询、方言、别名、插件及替换后的新结构均不作证明。模板不完整时不输出确定资源分类。
授权、净化、安全效果、运行绑定继续为未评估/未验证。

## 6. 预算与视图

保留原每文件256KiB、每操作输出4MiB限制。模板最多64个文本片段、128个标记、8层静态include，
遍历计数最多50,000；主要SQL材料仍有64项和每片段512词法单元的限制。
达到上限时标记truncated，不以部分列表声称完成。

full/summary/values均保留模板材料、条件和缺口。视图不改变context_id；注解模式与XML模式
绑定不同上下文。没有新增操作缓存，重复展开仍消耗解析资源。

## 7. 验证

```sh
make -f Makefile.security test
python3 tests/security/test_mybatis_templates.py build/security/cbm-security-facts
```

新增测试使用实际解析器和MCP，不执行测试Java业务逻辑。
`tests/mybatis-reference` 是独立、固定 MyBatis 3.5.19 的受控参考应用：只对仓库内测试模板取
BoundSql，比较参数顺序和已标记文本替换次数；不创建数据库连接、不执行查询。
执行结果以对应提交日志为准，测试基线不代表全部版本兼容或生产版本推荐。

开发核对资料：
https://mybatis.org/mybatis-3/sqlmap-xml.html
https://mybatis.org/mybatis-3/dynamic-sql.html
https://mybatis.org/mybatis-3/java-api.html

首轮独立参考发现：XML 单反斜杠的美元标记仍可能被替换，原实现将其排除错误。保留原失败
样例，并增加 CDATA、静态 include 和井号转义对照；不通过删除样例或放宽比较使其通过。

前置属性处理依据：
https://mybatis.org/mybatis-3/xref/org/apache/ibatis/parsing/XNode.html
https://mybatis.org/mybatis-3/xref/org/apache/ibatis/parsing/PropertyParser.html
