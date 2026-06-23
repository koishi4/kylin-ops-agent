# UML 图集索引（docs/uml/）

> 全部图用 **PlantUML**（文本源码 `.puml`）绘制，符合 UML 2.x / 软件工程制图规范，渲染为 PNG。
> 一图多用：同一批图同时进入「软件杯功能设计文档」「合工大软件工程课程报告」与「答辩 PPT」。

## 渲染方式

```bash
# 安装（Ubuntu/Debian）
sudo apt install -y default-jre graphviz plantuml fonts-noto-cjk fonts-wqy-zenhei
# 渲染全部图（在本目录执行）
export PLANTUML_LIMIT_SIZE=16384
plantuml -charset UTF-8 -tpng $(ls *.puml | grep -v _style.puml)
# 需要矢量图（插入 Word 更清晰）时改 -tsvg
```

`_style.puml` 是公共视觉样式（中文字体 Noto Sans CJK SC + 学术配色），各图 `!include` 复用，不单独渲染。

## 图清单与报告映射

| 文件 | 图号 | 类型 | 对应报告章节 |
|---|---|---|---|
| `usecase.puml` | 图2.1 | 用例图 | 需求分析 / 报告第2章 |
| `activity-ops.puml` | 图2.2 | 活动图（泳道，含护栏分支） | 需求分析 / 报告第2章 |
| `architecture.puml` | 图3.1 | 总体架构图（B/S 分层） | 功能设计 / 报告第3章 |
| `class-overview.puml` | 图3.2 | 主设计类图 | 功能设计 / 报告第3章 |
| `class-guardrail.puml` | 图4.1 | 护栏包详细类图（四道防线） | 功能设计 / 报告第4章 |
| `sequence-cleanup.puml` | 图4.2 | 顺序图（清理垃圾全链路） | 功能设计 / 报告第4章 |
| `sequence-injection.puml` | 图4.3 | 顺序图（抗提示词注入·CaMeL） | 功能设计 / 报告第4章 |
| `er-audit.puml` | 图4.4 | E-R 图（思维链审计库） | 功能设计 / 报告第4章 |
| `state-verdict.puml` | 图4.5 | 状态机图（护栏命令裁决） | 功能设计 / 报告第4章 |
| `deployment.puml` | 图5.1 | 部署图（LoongArch+麒麟V11） | 功能设计 / 报告第5章 |
| `component.puml` | 图5.2 | 构件图（模块与接口） | 功能设计 / 报告第5章 |

所有图号与正文图题在各文档中按「章序号.图序号」连续编号，符合合工大书写格式。
