# 固定 Spring MVC 注册对照

这不是扫描任意项目的运行功能。只编译并执行本目录的受控测试源码，
使用Spring Framework 6.2.6、Jakarta Servlet API 6.0.0。
版本作为固定对照，不是推荐生产版本或最新安全版本。
依赖下载仅发生在隔离测试任务，不给被审计目标开放执行或外网。

EntryOracle通过真实RequestMappingHandlerMapping收集注册结果，不手工填写预期路由。
compare.py将同一组源码交给CBM Sec的真实MCP进程，比较7个注册方法的路径、方法、params、headers、
consumes、produces共42个字段集合；另检查没有Controller标记的候选不冒充运行时注册。
没有HTTP监听、数据库、模型API或真实业务代码。结果不是任意Spring应用兼容性或授权正确性证明。

```sh
make -f Makefile.security
mvn -B -f tests/spring-reference/pom.xml compile dependency:build-classpath \
  -Dmdep.outputFile="$PWD/tests/spring-reference/target/deps.classpath"
java -cp "tests/spring-reference/target/classes:$(cat tests/spring-reference/target/deps.classpath)" \
  reference.EntryOracle > tests/spring-reference/target/reference.json
python3 tests/spring-reference/compare.py build/security/cbm-security-facts \
  tests/spring-reference/target/reference.json
```

独立CI：`.github/workflows/security-entry-reference.yml`，使用只读仓库权限，不访问用户密钥。
参考任务不混进Python专项测试总数。没有取得实际reference.json与compare成功日志时，不报告运行通过。
