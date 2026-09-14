# 快速开始

所有命令从可信的 **CBM Sec 工具仓库根目录**执行，不从被审计项目加载脚本。当前程序版本从 `security/facts.h` 读取；先确认所在分支包含 `security/` 和 `Makefile.security`。

## 构建

需要 C 编译器、Make、Python 3。两个生成的 C 程序运行时不依赖 Python；快照打包器、示例及测试需要 Python 3。源码打包器要求 POSIX。主要开发验证环境是 Linux x86_64。

```sh
make
build/security/cbm-security-facts --version
build/security/cbm-security-facts --capabilities
python3 security/demo_context.py --mcp build/security/cbm-security-mcp
python3 security/demo_trace.py --mcp build/security/cbm-security-mcp
```

`make -f Makefile.security` 保持兼容。`make` 不安装任何组件，不启动目标项目，也不调用模型。

## 查询一个文件

```sh
build/security/cbm-security-facts --path src/OrderController.java \
  < /path/to/read-only-snapshot/src/OrderController.java
```

`--path` 是逻辑文件身份；源码从标准输入读取。逻辑路径不构成外部文件读取权限。

## 准备 MCP 的固定源码包

先由宿主准备固定、只读的源码目录。将示例中的目录与文件列表替换为实际值；输出目录不得位于目标快照内。

```sh
set -eu
umask 077
WORK="$(mktemp -d)"
printf '%s\n' '["src/OrderController.java","src/OrderMapper.java","resources/OrderMapper.xml"]' > "$WORK/files.json"

python3 security/pack_snapshot.py \
  --root /path/to/read-only-snapshot --files "$WORK/files.json" \
  > "$WORK/snapshot.json" 2> "$WORK/snapshot.sha256"

build/security/cbm-security-mcp \
  --snapshot "$WORK/snapshot.json" \
  --expect-snapshot "$(cat "$WORK/snapshot.sha256")"
```

最后一条命令启动标准输入/输出协议服务，不是交互式终端界面。由 MCP 客户端用同一组参数启动它；本步骤不会代你修改客户端配置。

源码包是明确的文件集合，不是“全仓已扫描”的证明。它含完整源码，应放在私有产物目录。协议结果中的未知项、预算停止、解析错误和零路径必须分别处理。启动和缓存细节见 [MCP 参考](reference/mcp.md)。

## 常见问题

**首页介绍与本地能力不一致。** 先核对分支、提交、二进制 `--version` 与 `--capabilities`。本地候选包不自动等于远程分支。

**运行安装脚本后找不到安全工具。** 根目录的 `install.sh`、`install.ps1` 是保留的上游兼容安装器，不安装 CBM Sec。按本页从源码构建。

**查询中途停止。** 保存返回的覆盖记录和缺口。扩大范围或预算前确认停止原因；不要把空结果改写成“没有风险”。
