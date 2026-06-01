# 麒麟安全智能运维 Agent（软件杯 A2）

自然语言运维 Linux 的智能 Agent，核心是「安全护栏」。详见 docs/总方案.md。

## 快速开始
1. 读 CLAUDE.md（项目纲领）
2. 读 docs/总方案.md（环境配置 + 架构）
3. 按 docs/roadmap.md 推进

## 结构
- backend/   FastAPI 后端 + MCP Server + 护栏 + 审计
- frontend/  Vue3 B/S 界面
- docs/      方案、路线图、开发日志、UML 图
- .claude/skills/  三个开发技能（MCP工具/护栏/报告）
