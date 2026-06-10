# held-out 外部语料（去自评 / 防过拟合）

本目录放「**与护栏作者出题口径分离**」的 held-out 评测语料，配合
`scripts/redteam_eval.py --holdout <file>` 使用：

```
backend/.venv/bin/python scripts/redteam_eval.py --holdout scripts/corpora/holdout_sample.jsonl
```

## 为什么要它（评审痛点的测量层根治）

固定红队语料的「拦截率 100%」是「作者自己出题自己打分」。要把它变成可信评测，标准答案必须来自
**与作者无关、且未被用来调参**的源。两道机制：

1. **独立评测**：held-out 集**不混入**内置语料，单独「跑一次、如实报分」，**绝不**据它的失败回头调
   护栏——否则它就退化成训练集。
2. **内容指纹封存**：`<file>.sha256` 提交进仓库。每次跑都重算指纹并比对——一致即证明「这份集自
   封存以来未被改动」，分数才算「未对它调过参」的诚实评测；不一致说明被动过、分数不再可比。这把
   「我没拿这份卷子调过参」从口头承诺变成**可核验的事实**。

## 诚实声明（务必照实写进报告）

`holdout_sample.jsonl` 是一份**自制的、外部风格的示例集**，**不是**真实第三方数据集——它的作用是把
`--holdout` 机制跑通、演示「独立评测 + 指纹封存」这条流水线。真正的去自评应**接入真实外部基准**
（语料结构兼容，逐条至少含 `payload`，可选 `family` ∈ exec/inject/benign-exec/benign-inject）：

- **RedCode-Exec**（危险代码执行该不该被允许）
- **AgentDojo**（Agent 提示词注入端到端基准）
- **garak / DeepTeam**（LLM 越狱/注入 probe 集）

接入方式：把外部集转成本目录的 JSONL 格式、跑 `--holdout`、提交其 `.sha256`，并在报告里**如实**贴出
含失败的分数（而非只报好看的那部分）。
