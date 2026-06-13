# 误杀率独立评测报告 —— 第三方真实命令分布（NL2Bash held-out）

> 由 `scripts/benign_fp_eval.py` 自动生成。**破"自证"**：不再只在作者自选的良性集上测误杀，而是用
> 第三方为别的目的（NL→bash 翻译）收集的真实命令分布 TellinaTool/nl2bash@10963c9f418e 的**封存切片**独立度量。
> 封存校验 file_sha256 一致=True、sealed=True（证明评的就是封存那份，没挑没改）。

## 口径（诚实）
真实分布混着极少量真正危险命令，故**不**一律当良性。每条命令在两种操作者模型下各过一次产品真实
受控执行栈（dry_run 只裁决不落地）：
- **hard_fp（真·误杀）**：合法操作者模型（authorized∧confirmed）下**仍被硬拒**——已授权已确认还拒，
  等于把真实命令判成不可逆灾难(CRITICAL)。**核心指标。**
- **friction（最小权限摩擦）**：合法模型放行、最坏模型需授权/确认——赛题要求的"非必要不 root / 二次
  确认"在起作用，是设计不是误杀。
- **clean_pass**：最坏模型都直接放行。

## 结果（505 条真实命令）
| 类别 | 计数 | 占比 |
|---|---|---|
| ✗ 真·误杀 hard_fp（越低越好） | 3/505 | **0.6%** |
| · 最小权限摩擦 friction（by-design） | 226/505 | 44.8% |
| ✓ 直接放行 clean_pass | 276/505 | 54.6% |

## 真·误杀样例（逐条 verbatim，供审计）
- `nl2bash-1450`：`find /var/tmp/stuff -mtime +90 -execdir /bin/rm {} \+` — risk=critical rules=['PATH-001']
- `nl2bash-7525`：`find / -nouser -exec rm {} +` — risk=critical rules=['PATH-001']
- `nl2bash-7725`：`find . -name "*.txt" | sed "s/\.txt$//" | xargs -i echo mv {}.txt {}.bak | sh` — risk=critical rules=['AST-PIPELINE', 'AST-PIPE_TO_SHELL']

## 最小权限摩擦样例（前若干条，需授权/确认即可执行，非误杀）
- `nl2bash-0`：`top -b -d2 -s1 | sed -e '1,/USERNAME/d' | sed -e '1,/^$/d'`
- `nl2bash-100`：`yes 1 | command`
- `nl2bash-1000`：`find . -name '*.php' -type f | xargs wc -l`
- `nl2bash-10050`：`find . -size +1024 ?print|xargs -i rm \;`
- `nl2bash-10100`：`find . -type f -name “k*.*” -mmin -360 -exec ls -l ‘{}’ ; | xargs -0 /bin/rm -f`
- `nl2bash-10175`：`find . > files_and_folders`
- `nl2bash-10225`：`find -name "*.htm" | while read file; do sed "s|<title>sometext</title>|<title>${file##*/}</title>|g" -i $file; done`
- `nl2bash-1025`：`cat *.txt | wc -l`
- `nl2bash-1050`：`find . -name '*.js' -or -name '*.php' | xargs wc -l | grep 'total'  | awk '{ SUM += $1; print $1} END { print "Total text lines in PHP and JS",SUM }'`
- `nl2bash-10575`：`find $HOME/projects/ -name ".*" -ls > foo.txt`
- `nl2bash-10600`：`find | head`
- `nl2bash-10625`：`find . -type f | wc -l`
- `nl2bash-10700`：`find originals -name '*.jpg' | xargs -1 makeallsizes`
- `nl2bash-1075`：`find . -type d -print|sed 's@^@/usr/project/@'|xargs mkdir -p`
- `nl2bash-10975`：`find . -name "*.png" -print0 | xargs -0 mogrify -format jpg -quality 50`
