# Java 字符串返回依赖（开发更新）

本模块补充常见 `java.lang.String` 实例方法的返回依赖，复用现有局部值流、
同类函数返回摘要和自动上游追踪。没有增加 MCP 工具、危险类型或净化规则。

## 支持的签名

12 条签名模型覆盖 11 个方法名称：`trim()`、`strip()`、`stripLeading()`、
`stripTrailing()`、`toLowerCase()`、`toUpperCase()`、`substring(int)`、
`substring(int,int)`、`concat(String)`、`repeat(int)`、`replace(...)`、`toString()`。
`replace` 限制为两个明确字符或两个明确字符串；不读取任意 CharSequence 的对象内容。
`toString` 保留接收者的值关系，其余模型保守记录接收者与实参的可能变换依赖。
这不是精确字符串求值：长度、索引、替换文本都可能影响返回，不能据此证明字符可控。

## 类型、顺序与未知项

- 首先检查接收者类型，不能凭方法名把任意 `trim` / `toString` 当作标准库。
- 支持明确类型的形参和局部变量、字符串字面量、部分 `var` 推断、字符串拼接、
  明确转换以及同类受限返回摘要。保留数组维度，不把 String 数组当作 String。
- `java.lang.String` 和明确的 `import java.lang.String` 有各自的源码依据。
  仅依赖隐式导入的 `String` 可以产生条件候选，但保留
  `implicit_java_lang_String_requires_no_external_shadow` 未知项。
  当前文件不能证明其他未提供文件没有同包自定义 String 类型。
- 当前文件中的同名类型、类型参数、冲突导入、未解析通配导入、继承成员类型
  等会阻止相应模型；这不是完整 Java 名称或类型求解器。
- 接收者在参数前求值；参数从左到右。`s.concat(s="fixed")` 的接收者仍使用
  覆盖前的关系，而后续读取 s 使用新值。
- String 不可变操作不会改写接收者变量；`s.trim(); sink(s)` 不等于 s 被替换。
- 所有分析以合法 Java 程序、所匹配 JDK API 和正常返回为前提。
  异常、null、索引有效性、默认区域设置与路径可执行性均未证明。

## 输出与来源

`local_value_flow.library_models` 保存模型修订号、实际应用次数、类型环境访问量和范围。
`local_value_flow.evidence` 中的 `jdk_string_return_model` 记录 `model_id`、
`model_revision`、模型依据和原调用点引用。模型记录会随同类摘要复制到使用处，
不会把模型编号当成源码事实编号。

库模型进入已有 `inspect_operation_context` 和 `trace_source_to_sink`，不要求新增输入参数。
范围发现和检查点功能仍在单独的本地候选中，不属于本次远程增量。
旧的 origin/paths 兼容字段仍不是本次扩展的分析视图。

## 不代表净化

`trim`、`replace`、大小写转换不会清除数据依赖，模型的 `sanitizer` 均为 false。
调用返回尚未解析、分支包含未知来源、类型来自隐式假设时，已知关系与缺口并存。
`literal_possible` 表示存在不依赖形参的值来源，不意味着知道精确字符串或证明安全。

不支持静态 `String.valueOf`、`String.format`、区域设置重载、正则替换、StringBuilder、
任意自定义库、对象字段内容或数组传播。没有扩大源到点规则类别。

## 验证

```sh
make -f Makefile.security
python3 tests/security/test_string_models.py build/security/cbm-security-facts
```

另有 `tests/java-string-reference/` 中固定源码的 Java 运行对照。它检查有限输入扰动中
观察到的影响是否包含在静态结果中，不证明所有分支或所有输入的分析正确性。
只运行该仓库内受控测试程序，不运行被审计项目。

API 依据：Java SE 17 String；运行环境版本应从实际验证日志读取，不能由 --release 17 推断。
https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/String.html
https://docs.oracle.com/javase/specs/jls/se17/html/jls-15.html#jls-15.12.4
