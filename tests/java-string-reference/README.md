# Java 字符串模型独立对照

固定的 `StringReference.java` 含14个方法。每个方法使用一个基准输入以及四组
单参数变化，共70次正常返回。比较器将实际返回变化与静态形参依赖对照。

```sh
mkdir -p tests/java-string-reference/target
javac --release 17 -d tests/java-string-reference/target tests/java-string-reference/StringReference.java
java -version
java -cp tests/java-string-reference/target StringReference > tests/java-string-reference/target/reference.tsv
python3 tests/java-string-reference/compare.py build/security/cbm-security-facts tests/java-string-reference/target/reference.tsv
```

Java 17 是编译目标和文档依据，实际运行的 JDK 版本另行记录。
只比较已观察影响不能证明全域正确，也不能将未发生值变化判作无数据依赖。
不执行目标仓库的构建脚本、用户源码或数据库。普通 Python 专项测试不依赖 JDK。
