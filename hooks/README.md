# 可选的上下文提醒

技能是主要维护对象，钩子不是必需依赖。本脚本仅提供一次短提醒，不做扫描、分页、索引、报告审核或权限判定。
不读取工作目录、目标源码、聊天记录或事件中的路径；不执行命令、不联网、不写文件。事件字段不回显。
默认关闭。宿主明确设置 CBM_SEC_CONTEXT_ENABLED=1 和64位小写十六进制的 CBM_SEC_SNAPSHOT_ID 后才输出。
无效事件、未知事件、输入超过16 KiB、环境缺失时安静退出0，不阻塞调查。环境中的快照仍需与服务核对。

codex.example.json 是可选示例，不会自动写入任何客户端配置。部署者需要调整为受信任目录的绝对脚本路径，
按当前客户端文档检查字段并人工批准钩子。不要使用目标仓库路径定位脚本，不要绕过客户端的钩子信任机制。
仅绑定 SessionStart 的 startup/resume/compact 和 SubagentStart；不要同时绑定 PostCompact，以免重复注入。
不要绑定每次读文件或工具调用。失效、限额和强制隔离仍由宿主执行。

验证方式：
```sh
printf '%s' '{"hook_event_name":"SessionStart","source":"startup"}' | \
  CBM_SEC_CONTEXT_ENABLED=1 CBM_SEC_SNAPSHOT_ID=0000000000000000000000000000000000000000000000000000000000000000 \
  python3 hooks/cbm_sec_context.py
```

上例仅验证协议输出，不表示该快照存在。测试未启动真实Codex会话；实际钩子交付及信任状态需要在宿主验收。
官方核对依据（2026-09-12）：https://developers.openai.com/codex/hooks
技能格式：https://developers.openai.com/codex/skills 和 https://agentskills.io/specification
