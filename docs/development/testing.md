# 验证与发布边界

从本工具仓库根目录执行：

```sh
make docs-check
make test
```

文档检查覆盖中文入口、相对链接、工具表与源码的一致性、上游归档哈希和许可保留。它不验证外部网页当前可访问性，不代替程序测试。

安全回归仍通过 `Makefile.security` 构建两个程序并执行 C 核心及 `tests/security/test_*.py`。单独的内存检查构建：

```sh
ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
UBSAN_OPTIONS=halt_on_error=1 \
make -f Makefile.security test CC=clang BUILD=build/security-asan \
  CFLAGS='-O1 -g' SANITIZE='-fsanitize=address,undefined -fno-omit-frame-pointer'
```

## 参考实验不是业务漏洞评测

[Spring MVC](../../tests/spring-reference/README.md)、[MyBatis](../../tests/mybatis-reference/README.md)、[Spring Security](../../tests/spring-security-reference/README.md)和 [Java String](../../tests/java-string-reference/README.md) 使用固定测试版本与仓库内受控代码。测试代码存在不代表已运行；结果必须关联实际提交和日志。

源到点路径、净化效果、授权成立、动态复现与业务召回应分别记录。没有模型、真实宿主或业务仓库对照时，不宣称提高召回率或节省用量。

## 上游兼容测试

上游语言数量、客户端数量和发布策略测试仍检查被归档的上游材料，不要求 CBM Sec 继承这些宣传口径。改动复用组件时应补跑受影响的上游测试；本次目录整理没有删除测试或降低门槛。原 `tests/test_cli.c` 还硬编码根 README 与旧站点路径；其完整上游 C 回归尚未验证，相关路径断言需要后续迁移，不能据本项目文档检查宣布上游全绿。

## 发布

只发布明确请求的标签和测试过的产物；不覆盖历史 Release。文档整理不升级分析版本、不签署他人的贡献声明，也不自动合并功能 PR。当前状态见[交付记录](status.md)。
