# MyBatis 独立模板对照

只执行本目录中受控模板，固定 MyBatis 3.5.19。不使用外部目标工程，不连接数据库。
TemplateOracle 通过真实 MyBatis 获取 BoundSql；compare.py 将同一 Mapper/ XML 源码交给实际
CBM Sec MCP，检查活动分支中的参数顺序、标记到形参位置，以及可见文本替换次数。

14组样例包括XML与注解、字面量数组、SQL引号/注释、CDATA、转义、include和条件开/关。
compare.py 对两个固定条件的选择是测试期望，不是生产工具的条件求值器。
不证明SQL一定可以执行，也不证明对象授权、净化或漏洞成立。

从仓库根运行：

```sh
make -f Makefile.security
mvn -B -q -f tests/mybatis-reference/pom.xml compile dependency:build-classpath \
  -Dmdep.outputFile="$PWD/tests/mybatis-reference/target/deps.classpath"
java -cp "tests/mybatis-reference/target/classes:$(cat tests/mybatis-reference/target/deps.classpath)" \
  reference.TemplateOracle > tests/mybatis-reference/target/reference.json
python3 tests/mybatis-reference/compare.py build/security/cbm-security-facts \
  tests/mybatis-reference/target/reference.json
```

CI使用只读仓库权限，不取得生产凭据，不启动HTTP监听。版本固定用于复现，不是部署版本推荐。
