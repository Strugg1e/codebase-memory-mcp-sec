# 仓库结构与维护边界

本次整理针对远程 `e3b2716931caa634dd8ea850f79ffa2e64a6c6c1`。只调整产品入口、文档位置、构建导航、分发元数据归档和对应测试路径；不修改分析算法、不合入其他本地功能候选。

## 三个区域

| 区域 | 目录或文件 | 处理方式 |
|---|---|---|
| 安全产品 | `security/`、`skills/cbm-sec-evidence/`、`hooks/`、`tests/security/`、`Makefile.security` | 持续维护，文档与当前接口同步 |
| 复用依赖 | `internal/cbm/`、`src/foundation/`、`vendored/` | 保留路径、来源、许可证和完整性检查 |
| 上游兼容与参考 | 其他 `src/`、`graph-ui/`、`pkg/`、`Formula/`、`tools/`、`test-infrastructure/`、原安装器与构建 | 不作为 CBM Sec 默认入口；迁移前先核对脚本、测试和发布依赖 |

## 当前目录

```text
README.md / CONTRIBUTING.md / SECURITY.md   本项目中文入口
Makefile                                   默认构建 CBM Sec
Makefile.security                          既有安全构建契约
Makefile.cbm                               上游兼容构建，不自动执行
cbm-sec.json                               本项目导航元数据，不是包登记声明
security/                                  分析实现与源码打包、示例
skills/ / hooks/                           Agent 工具说明与可选提醒
tests/security/                            安全模块回归
tests/*-reference/                         独立受控参考实验
docs/
  README.md                                文档导航
  getting-started.md / tools.md             当前使用入口
  architecture.md                          产品职责
  development/                             结构、状态、验证、迁移清单
  reference/                               按主题组织的详细接口说明
  upstream/
    README.md                              上游来源索引
    originals/                             原 README、治理说明、登记元数据
    site/                                  原站点和上游技术文档
```

## 已处理

根目录的 `SECURITY_*.md` 迁到 `docs/reference/`，不再继续追加版本章节到首页。原版 README、维护者说明、安全政策和贡献说明按字节归档；本项目重新提供中文入口。

原 `server.json`、`glama.json` 的上游包和维护者信息迁入归档，不替换成尚未发布的 CBM Sec 包名。上游发布流程在其工作目录中显式取回原元数据，相关 Shell 元数据一致性测试也改为检查归档对象；没有删除或跳过原断言。

`.github/CODEOWNERS` 的建议负责人改为当前仓库所有者 `@Strugg1e`。这是待审查的仓库文件变更，不是直接修改 GitHub 分支保护；DCO、已有验证与发布审批保持原有检查。

## 为什么没有搬走全部上游代码

安全构建直接依赖语法路径、哈希组件和 JSON 库。原版构建、签名与包测试还引用其目录。一次移动 `internal/`、`src/` 或整个 `pkg/` 会把产品整理变成大规模兼容迁移，并增加尚未验证的发布行为。

因此，本轮先完成真实目录隔离与默认入口切换，不把“改名后能列目录”当作解耦成功。后续缩减依赖应独立提交，并用原有构建和针对性测试验证。

## 迁移记录

[机器可读清单](migration.json)记录旧路径、新路径、原始文件 SHA-256，以及未变更的许可文件。运行 `make docs-check` 可检查链接、归档哈希、工具表和错误的上游安装指引是否重新出现。

老版本标签及已有 Release 不会被改写。根文件路径迁移会影响硬编码这些路径的外部文档工具；调用者应按清单更新，分析可执行文件名和 MCP 工具名保持不变。
