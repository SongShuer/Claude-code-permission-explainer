# Permission Explainer

调用 AI 分析 Claude Code 每个工具操作的风险，用中文提前预警，把最终决策权交给你。

**背景：** 一位同学用 Claude Code 写代码，Agent 建议删个文件优化环境，他说"yes"，结果 C 盘被格式化了。所以有了这个插件。

## 效果

每次 Bash/Write/Edit/PowerShell 操作执行前，自动分析风险并拦截：

```
--- 权限解释 (中文) ---
🟠 风险: HIGH
做什么: 在终端执行命令: rm /important/data
为什么: 删除文件或目录，被删除的内容可能无法恢复
最坏情况: 重要文件被永久删除
------------------------
```

## 风险分级

| 等级 | 操作示例 | 插件行为 |
|------|---------|---------|
| 🟢 低 | `ls`、`echo`、`git status` | 直接放行 |
| 🟡 中 | 编辑/创建文件 | **拒绝 + 展示风险说明**，确认后重新执行 |
| 🟠 高 | `rm`、`sudo`、`chmod 777` | **拒绝 + 展示风险说明**，确认后重新执行 |
| 🔴 严重 | `rm -rf /`、`mkfs`、`dd if=` | **拒绝 + 展示风险说明**，确认后重新执行 |

## 安装

1. 复制整个目录到 `~/.claude/plugins/permission-explainer/`

2. 在 `~/.claude/settings.json` 配置 API（可选，不配置则用本地规则）：

```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "https://api.deepseek.com/anthropic",
    "ANTHROPIC_AUTH_TOKEN": "你的 DeepSeek API Key",
    "ANTHROPIC_MODEL": "deepseek-v4-pro"
  }
}
```

3. 在 `~/.claude/settings.local.json` 添加 hook：

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Write|Edit|PowerShell|WebFetch",
        "hooks": [
          {
            "type": "command",
            "command": "python ${CLAUDE_PLUGIN_ROOT}/hooks/explain.py",
            "timeout": 20
          }
        ]
      }
    ]
  }
}
```

4. 重启 Claude Code

## 工作原理

- **PreToolUse hook**：在工具执行前拦截
- **本地规则引擎**：300+ 行规则覆盖常见危险命令、敏感路径
- **DeepSeek API（可选）**：用 LLM 分析本地规则覆盖不到的场景
- **保守合并**：API 和本地规则取更高级别的风险，绝不降级
- **二次确认放行**：高风险操作首次 deny，用户在 120 秒内重新请求则自动放行

## 文件结构

```
permission-explainer/
├── .claude-plugin/
│   └── plugin.json          # 插件元数据
├── hooks/
│   ├── hooks.json           # Hook 配置
│   └── explain.py           # 核心分析脚本
├── skills/
│   └── explain-permission/
│       └── SKILL.md         # /explain-permission 技能
├── .gitignore
├── LICENSE
└── README.md
```

## 手动调用

在 Claude Code 中输入 `/explain-permission`，对当前权限提示做更详细的解释。

## 许可证

MIT
