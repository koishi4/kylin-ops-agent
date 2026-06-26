# 代码注释规范（软件工程学规范化）

> 本项目的注释/文档字符串实践，从「靠自觉」升级为「文档化、可执行、可进 CI」的强制标准。
> 强制由 [ruff](https://docs.astral.sh/ruff/) 的 pydocstyle（`D`）规则族落地，配置在 `backend/pyproject.toml`。
> 配套见 CLAUDE.md §6「代码注释充分」——注释质量直接计入文档评分，故把它当工程约束来管。

## 1. 一句话标准

**Google 风格中文 docstring**：模块、公开类、公开函数/方法、包（`__init__.py`）都要有 docstring；
首行是一句完整摘要，需要展开时空一行后写正文；参数/返回用 `Args:` / `Returns:` / `Raises:` 段。

```python
def find_large_files(path: str = "/", top_n: int = 10) -> dict:
    """在指定目录下查找占用空间最大的文件（评分④根因分析：磁盘满→定位大文件）。READONLY。

    Args:
        path: 起始目录，默认根目录。
        top_n: 返回最大的前 N 个文件，默认 10。
    Returns:
        含 files 列表（path/size_mb）的字典，按大小降序。
    """
```

## 2. 为什么用「中文 Google 风格」而不是英文 pydocstyle 全集

代码库注释是**中文**。pydocstyle 默认规则里有一批**英文正字法**规则，对中文文本不成立，
强行套用只会逼着把 ASCII 句号塞进中文、把不存在大小写的中文「首字母大写」，破坏可读性。
故在 `pyproject.toml` 里**显式禁用**这些规则，并写明理由：

| 规则 | 含义 | 为何对本库禁用 |
|---|---|---|
| `D415` | 首行须以 `.?!` 结尾 | 中文用 `。！？`，强加 ASCII 句号反而破坏文本 |
| `D403` | 首词须首字母大写 | 中文无大小写，规则无意义 |
| `D413` | 末段后须空行 | 英文段落习惯，对中文非必要（google 约定亦忽略） |
| `D105` | 魔术方法须 docstring | `__repr__`/`__enter__`/`__aexit__` 等签名与协议即语义 |
| `D107` | `__init__` 须 docstring | 类级 docstring 已说明职责，避免重复样板 |

保留的是对中文同样成立的**结构性/完整性**规则：缺 docstring（`D100`–`D104`）、
摘要与正文之间需空行（`D205`）、闭合引号换行（`D209`）、`Args:` 段完整且参数不漏（`D417`）、
含反斜杠须用裸字符串（`D301`）等。

## 3. 强制范围

- **生产代码 `backend/app/`**：完整 Google 风格，`ruff check app` 必须**零违规**。
- **测试 `tests/` 与脚本 `scripts/`**：强制「有模块/包 docstring」（交代用途），但其 docstring 是
  自由式说明，不强制 Google 段落格式，函数/类亦不强制 docstring（命名即说明）。

## 4. 怎么跑

```bash
cd backend && source .venv/bin/activate
ruff check app            # 生产代码：必须 All checks passed
ruff check app tests scripts   # 全量（含放宽过的测试/脚本）
ruff check app --statistics    # 看违规规则分布
ruff check app --fix           # 自动修复可机修项（D209 等格式类）
```

ruff 已加入 `backend/requirements.txt`。建议接入 CI 与 pre-commit，把 `ruff check app` 作为合并门禁。

## 5. 怎么扩展

- 新增生产代码：补齐 docstring 到通过 `ruff check app`，别用 `# noqa` 绕过——绕过等于没立规矩。
- 想再收紧（如给 `to_dict`/property 也要求 `Returns:`）：在 `pyproject.toml` 的 `select`/`ignore` 里调，
  改动连同理由记进 dev-log，保持「规则有据可查」。
- 切忌反向操作：为了让某段代码过线而把规则调松——和护栏「黑名单跑步机」一样，松规则是缓慢的失守。
