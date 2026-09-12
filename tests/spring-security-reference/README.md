# 固定 Spring Security 控制选择对照

测试基线：Spring Security 6.5.0、Spring Test 6.2.7、Servlet API 6.0.0。
固定版本是测试参考，不是生产推荐。只有此目录内的受控Java配置会运行。

SecurityOracle实际建立过滤链，读取FilterChainProxy中的顺序，使用框架匹配器选择链，
从真实授权管理器的注册项取得规则序号，并对匿名、普通和管理员三个测试身份调用管理器。
测试期反射只读取固定版本的mappings字段；字段不符时测试失败，不换用自造规则表。
不启动HTTP监听，不连接数据库，不执行被审计项目。
没有仅用最终403状态来证明规则选择，也没有运行完整HTTP过滤链或证明业务授权。

16组确定请求覆盖重叠链、规则顺序、方法差异、尾斜线、大小写、忽略列表、默认拒绝和无链。
另有2组自定义匹配器请求，真实结果必须在静态候选集合内；静态分析保持未知，不求值请求头。
测试类路径不包含Spring MVC；字符串重载只在这个明确参考前提下以ant-path假设查询。

```sh
make -f Makefile.security
mvn -B -q -f tests/spring-security-reference/pom.xml compile dependency:build-classpath \
  -Dmdep.outputFile="$PWD/tests/spring-security-reference/target/deps.classpath"
java -cp "tests/spring-security-reference/target/classes:$(cat tests/spring-security-reference/target/deps.classpath)" \
  reference.SecurityOracle > tests/spring-security-reference/target/reference.json
python3 tests/spring-security-reference/compare.py build/security/cbm-security-facts \
  tests/spring-security-reference/target/reference.json
```

此参考任务不属于无需Java的常规专项回归。是否已通过以本提交CI日志为准。
