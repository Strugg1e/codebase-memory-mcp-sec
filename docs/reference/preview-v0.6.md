# CBM Sec 0.6.0 Preview 1

这是 CBM Sec 独立工具的预览发布，不是上游 CBM 主程序的正式发行。
程序内部版本为 0.6.0，发布标签为 cbm-sec-v0.6.0-preview.1。
主分支、原安装器、生产配置和原有主程序发布流水线均不改变。

## 本次可用能力

多语言语法事实、框架声明候选、固定源码包、六个只读 MCP 工具，以及 Java/MyBatis 操作上下文。
新增最多四跳的显式上游调用路径校验。按位置关联未改写的直接形参，不靠名称跨函数连线。
不把用户提供的调用路径当成事实；每跳核对声明类型、目标方法及实参位置。

这不是完整污点引擎。没有自动调用者发现、局部别名/拼接/返回值传播、接口分派、
完整控制流、净化效果证明或漏洞自动判定。无法分析的关系保留缺口。
调用候选连通不等于所有参数都追踪成功，也不证明路径可执行或访问已获授权。

## 下载内容

- linux-x86_64.tar.gz：两个可执行文件、中文说明、许可证、源码打包器和可运行示例。
- source.tar.gz：固定发布提交的源码，可使用 Makefile.security 自行构建。
- SHA256SUMS：发行附件的 SHA-256 校验值，不是代码签名。
- BUILD_INFO.json：提交、工具版本、构建指纹、编译环境和构建运行链接。
- TEST_RESULTS.json：本次发布构建实际运行的专项测试统计。
- demo-flow-result.json：发布二进制运行示例得到的真实输出，不是业务仓库评测。

二进制仅在 Ubuntu 24.04 x86_64 构建和验证。其他 Linux 发行版可能受 glibc 版本影响；
Windows/macOS/ARM 不包含在本次二进制支持声明内。示例和打包器需要 Python 3 与 POSIX；
两个 C 工具本身不需要 Python 运行时。不需要模型密钥、Java、MyBatis 服务或业务数据库。

## 试用

从 Release 下载二进制包与 SHA256SUMS，在同一目录核对相应条目后解压：

```sh
sha256sum cbm-sec-v0.6.0-preview.1-linux-x86_64.tar.gz
# 将上面的值与 SHA256SUMS 中该文件对应的值比较；下载全部附件时可执行 sha256sum -c SHA256SUMS。
tar -xzf cbm-sec-v0.6.0-preview.1-linux-x86_64.tar.gz
cd cbm-sec-v0.6.0-preview.1-linux-x86_64
./bin/cbm-security-facts --version
python3 demo_flow.py --mcp ./bin/cbm-security-mcp
```

示例明确使用虚构测试源码，但通过真实 MCP 进程查询、取证和读取原始字节。
第一例将租户参数沿两跳追溯到请求注解候选；第二例覆盖参数后停止追踪。
两例都会保留 authorization_verdict=not_evaluated。示例成功不代表发现业务漏洞。

实际仓库需要先准备固定、只读源码目录，再用 pack_snapshot.py 显式选择文件，
把整个包的哈希作为可信启动参数。详细步骤见 docs/SECURITY_MCP.md；
多跳参数与停止条件见 docs/SECURITY_FLOW.md；Mapper/XML 范围见 docs/SECURITY_OPERATIONS.md。
源码包可能包含完整私有代码，不要提交到公开仓库。

## 发布质量与边界

预览包发布前，必须完成安全工具的 Clang 内存检查、GCC 构建、全部专项测试和
打包后示例回放。构建和发布权限分离；附件上传后重新下载校验，再将草稿转为公开预览。
不覆盖已有 Release，不改已有标签，不标为 Latest，不运行目标源码。

这些检查仅覆盖独立 CBM Sec 工具。DCO 贡献者署名、主项目 CodeQL 和全量回归仍按
原 PR 检查处理；预览发布不表示这些检查全部通过，也不等于批准合并主分支。
本次没有真实 Codex/Sulliu 会话、召回率、准确率或 Token 收益评测。
