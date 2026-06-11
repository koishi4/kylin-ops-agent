"""护栏：命令承载型包装器（xargs/timeout/watch/flock）的内嵌销毁命令必须被看穿。

背景（自测发现的真盲区，非 held-out 上补）：
  效果分析器原先按「首个非前缀词」取动词，xargs/timeout/watch/flock 会先吃掉自己的旗标/定位实参，
  其后才是真正执行的命令。于是 `xargs shred /boot/vmlinuz`、`watch -n1 truncate -s 0 /etc/hostname`、
  `xargs -I{} rm -rf /root` 的销毁动词被包装器名挡住，且恰好落在 rm 正则覆盖不到的路径/动词上 →
  整条命令被放行（实测 allow=True）。本测试锁定修复后的「看穿」行为，并用良性对照守住误杀率 0%。

纪律：危险样例只验「被拦/需确认」，绝不真正执行（全部走 check_command 静态裁决）。
"""
from __future__ import annotations

import pytest

from app.guardrail.effect_analyzer import analyze_effects
from app.guardrail.engine import check_command

# —— 包装器内嵌「销毁/外联落在关键区」的命令：必须不被静默放行（拦截或需确认） ——
# 选取标准：刻意挑 rm 正则覆盖不到的动词(shred/truncate)或路径(/root、/etc/hostname)，
# 确保命中靠的是「解包装器 + 按效果判定」，而非 rm 正则的巧合。
CARRIER_DANGEROUS = [
    "xargs shred /boot/vmlinuz",                 # shred 非 rm，/boot 关键
    "xargs -I{} rm -rf /root",                   # -I{} 模板，/root 关键（不在 DEL-003 正则）
    "watch -n1 truncate -s 0 /etc/hostname",     # watch 吃 -n1，内嵌 truncate 截断 /etc 文件
    "timeout 5 shred /etc/hostname",             # timeout 吃时长，内嵌 shred /etc
    "flock -x /tmp/l rm -rf /root",              # flock 吃 -x + 锁文件，内嵌 rm /root
    "timeout 5 xargs rm -rf /root",              # 嵌套包装：timeout→xargs→rm
    "nice xargs shred /boot/vmlinuz",            # 纯前缀 nice + 承载型 xargs 组合
]


@pytest.mark.parametrize("cmd", CARRIER_DANGEROUS)
def test_carrier_inner_destructive_is_contained(cmd):
    g = check_command(cmd, authorized=False, confirmed=False)
    assert not g.allowed, f"包装器内嵌销毁命令被放行（应拦截）：{cmd} -> {g.to_dict()}"


@pytest.mark.parametrize("cmd", [
    "xargs shred /boot/vmlinuz",
    "watch -n1 truncate -s 0 /etc/hostname",
    "timeout 5 shred /etc/hostname",
])
def test_carrier_inner_effect_is_seen(cmd):
    """效果分析器确实「看穿」到内嵌命令对关键区的删/截断效果（而非靠正则巧合）。"""
    e = analyze_effects(cmd)
    assert e.deletes or e.writes, f"未识别内嵌命令的关键区写/删效果：{cmd} -> {e.to_dict()}"


# —— 良性对照：包装器内嵌的是只读命令、或作用在非关键路径 → 绝不能被升级误杀 ——
CARRIER_BENIGN = [
    "xargs ls -la",                              # 内嵌只读 ls
    "timeout 5 systemctl status nginx",          # 只读状态查询
    "watch -n2 df -h",                           # 周期性看磁盘
    "xargs rm -rf /tmp/build",                   # rm 但作用在 /tmp（非关键）
    "timeout 10 tar -czf /tmp/etc.tgz /etc",     # 读 /etc 写 /tmp，备份属常规运维
    "xargs -n1 cat",                             # 内嵌 cat 读 stdin 指定文件（无关键操作数）
    "flock -x /tmp/l ls /var/log",               # flock 包裹只读 ls
]


@pytest.mark.parametrize("cmd", CARRIER_BENIGN)
def test_carrier_benign_not_escalated(cmd):
    g = check_command(cmd, authorized=False, confirmed=False)
    e = analyze_effects(cmd)
    # 良性内嵌不得产出「写/删关键区」效果（egress/fetch 由各自良性对照另测）
    assert not e.deletes and not e.writes, \
        f"良性包装器命令被误判出关键区写/删效果（误杀）：{cmd} -> {e.to_dict()}"
    # 放行或仅 pipeline/确认级，但绝不能因「解包装器」而升到 DENY
    assert g.allowed or g.require_confirm, \
        f"良性包装器命令被误拦为 DENY：{cmd} -> {g.to_dict()}"
