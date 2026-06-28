#!/usr/bin/env bash
# =============================================================================
# 麒麟虚机一键部署脚本（软件杯 A2：麒麟安全智能运维 Agent）—— 改进版 v3
# -----------------------------------------------------------------------------
# 目标环境：麒麟高级服务器操作系统 V11 + LoongArch（loongarch64），官方发放虚机。
#   也兼容其它 RPM(dnf/yum) / Debian(apt) 发行版与 x86_64（自动探测，便于本机预演）。
#
# === 相对 v1 的关键改动（都来自真实部署踩坑）===
#   ① 新增【Rust 工具链自愈】：loongarch 上 pydantic-core / jiter 等 Rust 扩展无预编译
#      wheel，只能源码编译；而麒麟自带 cargo 1.82 < 1.85，maturin 的 edition2024 解析失败。
#      本脚本在装 Python 依赖前先探测 cargo，版本不足/缺失则用 rustup（默认走清华镜像，
#      解决 VM 出网慢）自动升级到 stable。
#   ② 不再 dnf 安装 python3-pydantic：麒麟系统包是 pydantic 1.10.9(v1)，与项目所需 v2
#      不兼容，且在 --system-site-packages 下会污染 venv、挡住 pip 装 2.x。改为只复用系统
#      的 psutil/pyyaml，pydantic 一律在 venv 内装 v2（先探测，已是 v2 则跳过）。
#   ③ 放弃 --only-binary 探测：loongarch 上 pydantic-core 2.x 确认无 wheel，直接备好编译
#      环境后源码编译；编出的 wheel 会进 pip 缓存，重跑秒装。
#   ④ pip / rustup 默认走国内镜像（可 --pip-index / --rust-mirror 覆盖，或 --skip-rust 跳过）。
#
# === v3 修复（真机实测）===
#   ⑤ pip 镜像【加官方 PyPI 兜底】：清华源对 loongarch 索引不全，pydantic 等会返回
#      “from versions: none / No matching distribution”。用 --extra-index-url 让镜像缺失的
#      包自动回落官方源，既保留镜像加速、又不丢包。（可 --no-pip-fallback 关闭）
#   ⑥ pydantic 安装改为【先探测后装、不用 --ignore-installed】：>=2.6 约束本就让系统 1.x 不
#      满足、必装 v2 进 venv；--ignore-installed 反而每次强制重装、loongarch 上重复重编 pydantic-core，
#      既慢又易在网络抖动时报错。已是 v2 直接跳过，幂等重跑不再空跑编译。
#
# 用法：
#   bash scripts/deploy_kylin.sh                      # 默认：拉到 /opt、mock 离线、不建服务
#   bash scripts/deploy_kylin.sh --systemd            # 额外建 opsagent + systemd 开机自启（推荐）
#   bash scripts/deploy_kylin.sh --provider deepseek --api-key sk-xxx
#   bash scripts/deploy_kylin.sh --skip-rust          # 已自备 Rust>=1.85 时跳过 rustup
#   bash scripts/deploy_kylin.sh --pip-index ""       # 完全用官方 PyPI（不走镜像）
#   bash scripts/deploy_kylin.sh --help
# =============================================================================
set -euo pipefail

# ---------- 可配置默认值（命令行参数可覆盖） ----------
REPO_URL="https://github.com/koishi4/kylin-ops-agent.git"
BRANCH="main"
INSTALL_DIR="/opt/kylin-ops-agent"
LLM_PROVIDER="mock"
DEEPSEEK_API_KEY=""
BIND_HOST="127.0.0.1"
PORT="8000"
EXEC_USER="opsagent"
DO_SYSTEMD=0
DO_NGINX=0
SKIP_TESTS=0
SKIP_SYSDEPS=0
SKIP_RUST=0                  # 1=不碰 Rust（已自备 >=1.85 时用）
RUST_MIN="1.85"              # pydantic-core/maturin 的 edition2024 所需最低 cargo
PIP_INDEX="https://pypi.tuna.tsinghua.edu.cn/simple"          # pip 国内镜像（空字符串=用官方默认）
RUST_MIRROR="https://mirrors.tuna.tsinghua.edu.cn/rustup"     # rustup 工具链镜像（空=官方）
PIP_FALLBACK_URL="https://pypi.org/simple"                    # 镜像缺包时的兜底源（官方 PyPI）
NO_PIP_FALLBACK=0            # 1=不加兜底源（仅当你确信镜像对 loongarch 索引完整时）

# ---------- 彩色日志 ----------
if [ -t 1 ]; then C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_B=$'\033[36m'; C_0=$'\033[0m'
else C_G=; C_Y=; C_R=; C_B=; C_0=; fi
log()  { printf '%s==>%s %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '%s ✓ %s%s\n' "$C_G" "$*" "$C_0"; }
warn() { printf '%s ! %s%s\n' "$C_Y" "$*" "$C_0" >&2; }
die()  { printf '%s ✗ %s%s\n' "$C_R" "$*" "$C_0" >&2; exit 1; }

usage() { awk 'NR==1{next} /^#/{sub(/^# ?/,"");print;next} {exit}' "$0"; exit 0; }

# 版本比较：ver_ge A B → 当 A>=B 为真（按语义版本排序）
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]; }

# ---------- 解析参数 ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --repo)       REPO_URL="$2"; shift 2 ;;
    --branch)     BRANCH="$2"; shift 2 ;;
    --dir)        INSTALL_DIR="$2"; shift 2 ;;
    --provider)   LLM_PROVIDER="$2"; shift 2 ;;
    --api-key)    DEEPSEEK_API_KEY="$2"; shift 2 ;;
    --bind)       BIND_HOST="$2"; shift 2 ;;
    --port)       PORT="$2"; shift 2 ;;
    --user)       EXEC_USER="$2"; shift 2 ;;
    --systemd)    DO_SYSTEMD=1; shift ;;
    --nginx)      DO_NGINX=1; shift ;;
    --skip-tests) SKIP_TESTS=1; shift ;;
    --skip-sysdeps) SKIP_SYSDEPS=1; shift ;;
    --skip-rust)  SKIP_RUST=1; shift ;;
    --pip-index)  PIP_INDEX="$2"; shift 2 ;;
    --rust-mirror) RUST_MIRROR="$2"; shift 2 ;;
    --no-pip-fallback) NO_PIP_FALLBACK=1; shift ;;
    -h|--help)    usage ;;
    *) die "未知参数：$1（用 --help 看用法）" ;;
  esac
done

# pip 镜像：export 后所有 pip 调用自动生效
if [ -n "$PIP_INDEX" ]; then export PIP_INDEX_URL="$PIP_INDEX"; fi

# pip 兜底源：仅当启用了镜像、且未 --no-pip-fallback 时，附加官方 PyPI 作 extra-index。
# 这样清华缺的包（loongarch 上的 pydantic 等会报 “from versions: none”）会自动回落官方源。
# 注意：$PIP_FALLBACK 不加引号是要让它在命令行里展开成两个独立 argv（--extra-index-url 与 URL）。
PIP_FALLBACK=""
if [ -n "$PIP_INDEX" ] && [ "$NO_PIP_FALLBACK" -eq 0 ] && [ -n "$PIP_FALLBACK_URL" ]; then
  PIP_FALLBACK="--extra-index-url $PIP_FALLBACK_URL"
fi

# ---------- sudo 包装 ----------
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else
    warn "当前非 root 且无 sudo：将跳过需要提权的步骤（装系统包/建账户/systemd）。"
    SUDO=""; SKIP_SYSDEPS=1; DO_SYSTEMD=0; DO_NGINX=0
  fi
fi

# ---------- 0. 环境探测 ----------
log "[0/8] 探测运行环境"
ARCH="$(uname -m)"
. /etc/os-release 2>/dev/null || true
OS_PRETTY="${PRETTY_NAME:-$(uname -srm)}"
KYLIN_REL="$(cat /etc/kylin-release 2>/dev/null || true)"
printf '    架构: %s\n    系统: %s\n' "$ARCH" "$OS_PRETTY"
[ -n "$KYLIN_REL" ] && printf '    麒麟: %s\n' "$KYLIN_REL"
[ -n "$PIP_INDEX" ] && printf '    pip 镜像: %s%s\n' "$PIP_INDEX" "$([ -n "$PIP_FALLBACK" ] && echo '  (+官方 PyPI 兜底)')"
if [ "$ARCH" = "loongarch64" ]; then
  ok "LoongArch 目标架构（注意：pydantic-core/jiter 等 Rust 扩展需源码编译，本脚本已备 Rust 自愈）"
else
  warn "非 loongarch64（$ARCH）：多为本机预演。LoongArch 专属适配点（Rust 编译等）按需自动跳过。"
fi

PKG=""
if   command -v dnf >/dev/null 2>&1; then PKG="dnf"
elif command -v yum >/dev/null 2>&1; then PKG="yum"
elif command -v apt-get >/dev/null 2>&1; then PKG="apt"
fi
[ -n "$PKG" ] && printf '    包管理器: %s\n' "$PKG" || warn "未识别包管理器，将跳过系统依赖安装。"

# ---------- 1. 安装系统依赖 ----------
log "[1/8] 安装系统依赖（Python/编译链/系统采集工具）"
if [ "$SKIP_SYSDEPS" -eq 1 ] || [ -z "$PKG" ]; then
  warn "跳过系统依赖安装。请自行确保 python3(>=3.11)/gcc/openssl-devel/lsof/ss 等就绪。"
else
  case "$PKG" in
    dnf|yum)
      # 关键：psutil/pyyaml 用系统包（loongarch 上已预编译，省去 C 扩展编译）。
      #       gcc/make/python3-devel/openssl-devel/perl 为 Rust+C 扩展编译兜底。
      #       ★ 不再安装 python3-pydantic：麒麟系统包是 v1(1.10.9)，与项目所需 v2 冲突且会污染 venv。
      $SUDO "$PKG" install -y \
        git curl python3 python3-pip python3-devel gcc gcc-c++ make \
        openssl-devel perl \
        python3-psutil python3-pyyaml \
        sqlite lsof iproute procps-ng \
        || warn "部分系统包安装失败（源中可能无此包名）：稍后 pip/编译兜底，必要时见 docs/deploy-loongarch.md §2。"
      ;;
    apt)
      $SUDO apt-get update -y || true
      $SUDO apt-get install -y \
        git curl python3 python3-venv python3-pip python3-dev build-essential \
        libssl-dev perl \
        python3-psutil python3-yaml \
        sqlite3 lsof iproute2 procps \
        || warn "部分 apt 包安装失败，pip/编译兜底。"
      ;;
  esac
  ok "系统依赖处理完成"
fi

# 选 Python 解释器
PY=""
for c in python3.11 python3; do
  command -v "$c" >/dev/null 2>&1 && { PY="$c"; break; }
done
[ -n "$PY" ] || die "未找到 python3，请先安装 Python 3.11。"
PYVER="$("$PY" -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
printf '    Python: %s (%s)\n' "$PYVER" "$("$PY" -c 'import sys;print(sys.executable)')"
case "$PYVER" in
  3.11|3.12|3.13) ok "Python 版本满足（>=3.11）" ;;
  3.10) warn "Python 3.10：项目用到 3.10+ 的 X|Y 标注，应能跑；建议升 3.11。" ;;
  *) warn "Python $PYVER 低于 3.11，可能有语法不兼容。" ;;
esac

for t in lsof ss journalctl df free ps; do
  command -v "$t" >/dev/null 2>&1 && printf '    [tool] %-10s ✓\n' "$t" \
    || warn "缺少 $t：相关 MCP 感知工具可能降级（非致命）。"
done

# ---------- 1.5 Rust 工具链自愈 ----------
# 仅当目标架构无预编译 wheel（loongarch64）且未 --skip-rust 时处理。x86 上 pip 直接下 wheel，无需 Rust。
log "[1.5/8] Rust 工具链检查（pydantic-core/jiter 在 loongarch 上需源码编译）"
ensure_rust() {
  local cur=""
  if command -v cargo >/dev/null 2>&1; then
    cur="$(cargo --version 2>/dev/null | awk '{print $2}')"
  fi
  if [ -n "$cur" ] && ver_ge "$cur" "$RUST_MIN"; then
    ok "cargo $cur 已满足（>=$RUST_MIN），无需处理"
    return 0
  fi
  [ -n "$cur" ] && warn "cargo $cur 过旧（需 >=$RUST_MIN，maturin 的 edition2024 不被支持）" \
                || warn "未检测到 cargo"
  log "通过 rustup 安装/升级 Rust stable（镜像：${RUST_MIRROR:-官方}）"
  if [ -n "$RUST_MIRROR" ]; then
    export RUSTUP_DIST_SERVER="$RUST_MIRROR"
    export RUSTUP_UPDATE_ROOT="$RUST_MIRROR/rustup"
  fi
  if command -v rustup >/dev/null 2>&1; then
    rustup update stable && rustup default stable
  else
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | sh -s -- -y --default-toolchain stable --profile minimal \
      || die "rustup 安装失败：VM 出网可能受限。可换 --rust-mirror，或在联网机下 loongarch64 工具链离线拷入（见 docs/deploy-loongarch.md §2 策略 B）。"
  fi
  # shellcheck disable=SC1091
  [ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"
  command -v cargo >/dev/null 2>&1 || die "cargo 安装后仍不可用，请检查 PATH（source \$HOME/.cargo/env）。"
  cur="$(cargo --version | awk '{print $2}')"
  ver_ge "$cur" "$RUST_MIN" && ok "Rust 就绪：cargo $cur" \
    || die "cargo $cur 仍低于 $RUST_MIN，请手工 rustup update。"
}
if [ "$SKIP_RUST" -eq 1 ]; then
  warn "按 --skip-rust 跳过 Rust 处理（请确保 cargo>=$RUST_MIN，否则 pydantic-core 编译会失败）。"
  [ -f "$HOME/.cargo/env" ] && { source "$HOME/.cargo/env"; } || true
elif [ "$ARCH" = "loongarch64" ]; then
  ensure_rust
else
  ok "非 loongarch64：pydantic-core 通常有预编译 wheel，跳过 Rust 处理。"
fi

# ---------- 2. 从 GitHub 拉代码 ----------
log "[2/8] 拉取代码：$REPO_URL ($BRANCH) → $INSTALL_DIR"
PARENT_DIR="$(dirname "$INSTALL_DIR")"
$SUDO mkdir -p "$PARENT_DIR"
# git 2.35.2+ 的「dubious ownership」闸门：仓库目录属主 ≠ 操作者 时直接拒绝所有操作。本脚本上一次
# --systemd 跑会把整树 chown 给 opsagent，于是【重跑】时 step2 的 git（经 $SUDO 以 root 跑、但 git 会
# 按 SUDO_UID=vmuser 比对属主）就会因「属主 opsagent ≠ vmuser」致命退出（真机实测踩到）。
# 兜底要稳：① 每条 git 一律【内联】-c safe.directory，与 HOME/属主/是否 sudo 全解耦，最可靠；
#          ② 另把例外写进 root 与当前用户的全局配置，双保险。注意 $GSAFE 不加引号是要让它按空白
#             拆成「-c」「safe.directory=…」两个独立 argv（INSTALL_DIR 默认无空格）。
GSAFE="-c safe.directory=$INSTALL_DIR"
git config --global --add safe.directory "$INSTALL_DIR" 2>/dev/null || true
[ -n "$SUDO" ] && $SUDO git config --global --add safe.directory "$INSTALL_DIR" 2>/dev/null || true
if [ -d "$INSTALL_DIR/.git" ]; then
  log "已存在仓库，执行更新（fetch + reset 到 origin/$BRANCH）"
  $SUDO git $GSAFE -C "$INSTALL_DIR" remote set-url origin "$REPO_URL"
  $SUDO git $GSAFE -C "$INSTALL_DIR" fetch --depth 1 origin "$BRANCH"
  $SUDO git $GSAFE -C "$INSTALL_DIR" checkout -B "$BRANCH" "origin/$BRANCH"
  $SUDO git $GSAFE -C "$INSTALL_DIR" reset --hard "origin/$BRANCH"
else
  [ -e "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ] \
    && die "$INSTALL_DIR 已存在且非 git 仓库且非空，请清理或换 --dir。"
  $SUDO git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
fi
[ -n "$SUDO" ] && $SUDO chown -R "$(id -u):$(id -g)" "$INSTALL_DIR" || true
# 此刻（step6 chown 给 opsagent 之前）把 HEAD 描述缓存进变量，收尾摘要直接用它，避免 chown 后再调
# git 又撞 dubious ownership / 显示空 commit。git 调用仍内联 $GSAFE，属主刚被换也不受影响。
GIT_HEAD="$(git $GSAFE -C "$INSTALL_DIR" rev-parse --short HEAD 2>/dev/null || echo '?')"
GIT_SUBJECT="$(git $GSAFE -C "$INSTALL_DIR" log -1 --pretty=%s 2>/dev/null | cut -c1-50)"
ok "代码就位：$GIT_HEAD $GIT_SUBJECT"

BACKEND="$INSTALL_DIR/backend"
FRONTEND="$INSTALL_DIR/frontend"
[ -d "$BACKEND" ] || die "未找到 backend/ 目录，仓库结构异常。"

# ---------- 3. 后端 venv + Python 依赖 ----------
log "[3/8] 创建后端虚拟环境并安装 Python 依赖"
cd "$BACKEND"
# --system-site-packages：让系统包的 psutil 对 venv 可见，避免编译 C 扩展。
# 注意：系统还带 pydantic 1.x，会被 venv 内 2.x 覆盖（sys.path venv 优先），下面装 pydantic 时强制处理。
[ -d .venv ] || "$PY" -m venv --system-site-packages .venv
# shellcheck disable=SC1091
source .venv/bin/activate
# 确保编译期能找到新装的 cargo（rustup 装在 ~/.cargo）
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env" || true
python -m pip install --upgrade pip >/dev/null

# 由 requirements.txt 生成 LoongArch 友好清单：uvicorn[standard] → uvicorn
# （去掉 uvloop/httptools/watchfiles 等编译大头；启动加 --loop asyncio --http h11 即可）
REQ_SRC="requirements.txt"; [ -f "$REQ_SRC" ] || die "缺少 backend/requirements.txt"
REQ_TMP="$(mktemp)"; trap 'rm -f "$REQ_TMP"' EXIT
sed -E 's/uvicorn\[[^]]*\]/uvicorn/' "$REQ_SRC" > "$REQ_TMP"

# 先确保 venv 内 pydantic 为 v2：
#   - 已是 v2 → 跳过（幂等重跑不再空跑编译）。
#   - 否则装 >=2.6：该约束本就让系统 1.x 不满足、必装 v2 进 venv，不需要 --ignore-installed
#     （后者每次强制重装、loongarch 上重复重编 pydantic-core，慢且易在网络抖动时失败）。
#   - 走 $PIP_FALLBACK（官方 PyPI 兜底）：清华对 loongarch 索引不全，pydantic 在镜像上会返回
#     “from versions: none”，回落官方源才能取到源码包并编译。
log "确保 venv 内 pydantic 为 v2（≥2.6）"
if python -c 'import pydantic,sys; sys.exit(0 if str(getattr(pydantic,"VERSION","")).startswith("2.") else 1)' 2>/dev/null; then
  ok "venv 内已是 pydantic v2，跳过（不重装、不重编 pydantic-core）"
else
  log "安装 pydantic v2（loongarch 上将编译 pydantic-core，约 10 分钟，CPU 跑满属正常，勿 Ctrl-C）"
  pip install $PIP_FALLBACK "pydantic>=2.6" \
    || warn "pydantic v2 安装失败：检查 [1.5] cargo 版本与出网；若镜像取不到包可试 --pip-index \"\" 用官方源。"
fi

log "安装其余依赖"
if ! pip install $PIP_FALLBACK -r "$REQ_TMP"; then
  warn "整体安装有失败项，逐行重试以定位。"
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    pkg="${line%%#*}"; pkg="$(echo "$pkg" | xargs)"
    [ -z "$pkg" ] && continue
    pip install $PIP_FALLBACK "$pkg" || warn "依赖安装失败：$pkg（继续，稍后冒烟检验）"
  done < "$REQ_TMP"
fi

# 关键扩展可导入性自检（不含 openai：mock 模式不需要；jiter 失败不影响离线演示）
python - <<'PYCHK' || die "关键依赖导入失败，请按上方提示处理（多为 cargo 版本不足导致 pydantic-core 未编译成功）。"
import importlib, sys
need = ["fastapi", "uvicorn", "psutil", "pydantic", "yaml", "mcp", "httpx", "aiosqlite", "bashlex"]
miss = []
for m in need:
    try: importlib.import_module(m)
    except Exception as e: miss.append(f"{m} ({e.__class__.__name__})")
if miss:
    print("  缺失/不可导入: " + ", ".join(miss)); sys.exit(1)
import psutil, pydantic
v = getattr(pydantic, "VERSION", "?")
print(f"  deps ok  psutil={psutil.__version__}  pydantic={v}  ({pydantic.__file__})")
assert str(v).startswith("2."), f"pydantic 必须是 v2，当前 {v}（疑被系统 1.x 覆盖，请加 --force-reinstall 重装）"
PYCHK
ok "后端依赖就绪"

# ---------- 4. 写 .env 配置 ----------
log "[4/8] 写后端 .env 配置（provider=$LLM_PROVIDER, bind=$BIND_HOST）"
[ -f .env ] || cp .env.example .env
set_env() { local k="$1" v="$2"
  if grep -qE "^${k}=" .env; then sed -i -E "s|^${k}=.*|${k}=${v}|" .env
  else printf '%s=%s\n' "$k" "$v" >> .env; fi
}
set_env LLM_PROVIDER "$LLM_PROVIDER"
set_env API_BIND_HOST "$BIND_HOST"
set_env EXEC_USER "$EXEC_USER"
if [ "$LLM_PROVIDER" = "deepseek" ]; then
  if [ -n "$DEEPSEEK_API_KEY" ]; then set_env DEEPSEEK_API_KEY "$DEEPSEEK_API_KEY"
  else warn "provider=deepseek 但未给 --api-key：请手工在 $BACKEND/.env 填 DEEPSEEK_API_KEY。"; fi
fi
case "$BIND_HOST" in
  127.0.0.1|localhost|::1)
    # 回环=演示模式：受控动作鉴权应「留空=不强制」（require_operator 见 token 为空即放行）。
    # .env.example 出厂是占位串 please-change-me（非空）——它会让 /action/execute【强制】鉴权，而随 git
    # 下发的前端 dist 是用【空】VITE_OPERATOR_TOKEN 构建的、不带 token → 受控动作必 401、演示当场失效。
    # 故回环部署把占位串清空，回到设计本意的「本机可信控制台演示模式」。要鉴权请显式 --bind 非回环，
    # 或手工设 OPERATOR_TOKEN 并用同值 VITE_OPERATOR_TOKEN 重新构建前端。
    if grep -qE '^OPERATOR_TOKEN=please-change-me$' .env; then
      set_env OPERATOR_TOKEN ""
      warn "回环演示模式：已清空占位 OPERATOR_TOKEN（受控动作不强制鉴权）。注意：--nginx 会把 /api 暴露到"
      warn "本机 80 端口，同网段可达——演示环境可接受；生产请配 token 并用同值重建前端 dist。"
    fi
    ;;
  *)
    if grep -qE '^OPERATOR_TOKEN=(please-change-me)?$' .env; then
      TOK="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
      set_env OPERATOR_TOKEN "$TOK"
      warn "对外绑定（$BIND_HOST）：已生成 OPERATOR_TOKEN（见 .env）；前端 VITE_OPERATOR_TOKEN 需设同值。"
    fi
    if grep -qE '^AUDIT_HMAC_KEY=kylin-ops-agent-audit-chain-v1$' .env; then
      set_env AUDIT_HMAC_KEY "kylin-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
      warn "已为对外部署生成独立 AUDIT_HMAC_KEY。"
    fi
    ;;
esac
ok ".env 配置完成：$BACKEND/.env"

# ---------- 5. 前端 dist ----------
log "[5/8] 处理前端静态产物"
if [ -d "$FRONTEND/dist" ] && [ -n "$(ls -A "$FRONTEND/dist" 2>/dev/null)" ]; then
  ok "仓库已带 frontend/dist（不在 LoongArch 构建，直接托管）。"
elif command -v npm >/dev/null 2>&1; then
  warn "未见 dist 但检测到 npm：尝试本机构建（LoongArch 上非推荐路径）。"
  ( cd "$FRONTEND" && (npm ci --silent || npm install --silent) && npm run build ) \
    && ok "前端构建完成 → frontend/dist" \
    || warn "前端构建失败：请在 x86 开发机 build 后把 dist/ 拷过来。"
else
  warn "无 dist 且无 npm：请在 x86 开发机构建后将 frontend/dist 拷到 $FRONTEND/。"
fi

# ---------- 6. 最小权限账户 + systemd（可选） ----------
log "[6/8] 最小权限账户 + systemd 服务"
if [ "$DO_SYSTEMD" -eq 1 ]; then
  [ -n "$SUDO" ] || [ "$(id -u)" -eq 0 ] || die "--systemd 需要 root/sudo。"
  if ! id "$EXEC_USER" >/dev/null 2>&1; then
    $SUDO useradd -r -s /usr/sbin/nologin "$EXEC_USER" 2>/dev/null \
      || $SUDO useradd -r -s /sbin/nologin "$EXEC_USER" \
      || warn "创建 $EXEC_USER 失败（可能已存在或 nologin 路径不同）。"
    id "$EXEC_USER" >/dev/null 2>&1 && ok "已创建受限账户 $EXEC_USER"
  else
    ok "受限账户 $EXEC_USER 已存在"
  fi
  $SUDO chown -R "$EXEC_USER":"$EXEC_USER" "$INSTALL_DIR"
  UNIT=/etc/systemd/system/kylin-ops-agent.service
  $SUDO tee "$UNIT" >/dev/null <<UNITEOF
[Unit]
Description=Kylin Ops Agent (软件杯 A2 安全智能运维 Agent)
After=network.target

[Service]
User=$EXEC_USER
Group=$EXEC_USER
WorkingDirectory=$BACKEND
ExecStart=$BACKEND/.venv/bin/uvicorn app.main:app --host $BIND_HOST --port $PORT --loop asyncio --http h11
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
UNITEOF
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now kylin-ops-agent
  ok "systemd 服务已安装并启动：systemctl status kylin-ops-agent"
else
  warn "未加 --systemd：跳过 opsagent 账户与开机自启。可手工前台启动（见末尾）。"
fi

# ---------- 6.5 nginx（可选） ----------
if [ "$DO_NGINX" -eq 1 ]; then
  log "[6.5] 配置 nginx 托管前端 dist 并反代 /api → 127.0.0.1:$PORT"
  if command -v nginx >/dev/null 2>&1 || $SUDO "$PKG" install -y nginx 2>/dev/null; then
    NGX=/etc/nginx/conf.d/kylin-ops-agent.conf
    $SUDO tee "$NGX" >/dev/null <<NGXEOF
server {
    listen 80;
    server_name _;
    root $FRONTEND/dist;
    index index.html;
    location /api/ { proxy_pass http://127.0.0.1:$PORT/; proxy_set_header Host \$host; }
    location / { try_files \$uri \$uri/ /index.html; }
}
NGXEOF
    $SUDO nginx -t && $SUDO systemctl enable --now nginx && $SUDO systemctl reload nginx \
      && ok "nginx 已托管前端（http://<本机IP>/），/api 反代到后端。" \
      || warn "nginx 校验/重载失败，请检查 $NGX。"
  else
    warn "未能安装 nginx，跳过。"
  fi
fi

# ---------- 7. 冒烟自检 ----------
log "[7/8] 冒烟自检（离线 mock 跑测试 + 起服务探活）"
cd "$BACKEND"
if [ "$SKIP_TESTS" -eq 1 ]; then
  warn "按 --skip-tests 跳过 pytest 回归。"
else
  log "pytest 全套回归（LLM_PROVIDER=mock，离线确定）"
  # cache_dir 指到可写临时目录：step6 已把仓库 chown 给 opsagent，pytest 以 vmuser 跑会无法在
  # 树内写 .pytest_cache（Permission denied 告警）。指到 /tmp 既消除告警、又不污染部署目录。
  if LLM_PROVIDER=mock PYTHONPATH=. python -m pytest -q -o cache_dir=/tmp/kylin-ops-pytest-cache; then
    ok "pytest 全绿（LoongArch 适配成功最硬的证据）。"
  else
    warn "pytest 有未通过项：root/容器环境有已知差异（kill 授权、沙箱内存归因），其余请核查。"
  fi
fi

probe() { curl -sf --noproxy '*' --max-time 5 "http://127.0.0.1:$PORT$1"; }
HEALTH_OK=0
if [ "$DO_SYSTEMD" -eq 1 ]; then
  for _ in $(seq 1 15); do probe /health >/dev/null 2>&1 && { HEALTH_OK=1; break; }; sleep 1; done
else
  log "临时拉起后端探活（mock）"
  ( LLM_PROVIDER="$LLM_PROVIDER" .venv/bin/uvicorn app.main:app --host 127.0.0.1 --port "$PORT" \
      --loop asyncio --http h11 >/tmp/kylin-ops-smoke.log 2>&1 ) &
  SMOKE_PID=$!
  for _ in $(seq 1 20); do probe /health >/dev/null 2>&1 && { HEALTH_OK=1; break; }; sleep 1; done
fi
if [ "$HEALTH_OK" -eq 1 ]; then
  ok "/health  → $(probe /health || true)"
  TOOLS_N="$(probe /tools | python -c 'import sys,json;d=json.load(sys.stdin);print(len(d.get("tools",d) if isinstance(d,dict) else d))' 2>/dev/null || echo '?')"
  ok "/tools   → 列出 $TOOLS_N 个 MCP 工具"
else
  warn "探活失败：看 /tmp/kylin-ops-smoke.log 或 journalctl -u kylin-ops-agent。"
fi
[ -n "${SMOKE_PID:-}" ] && kill "$SMOKE_PID" >/dev/null 2>&1 || true

# ---------- 8. 收尾提示 ----------
log "[8/8] 部署完成"
cat <<SUMMARY

${C_G}====================== 部署摘要 ======================${C_0}
  代码目录   : $INSTALL_DIR  (${GIT_HEAD:-?} ${GIT_SUBJECT:-})
  后端       : $BACKEND  (venv: .venv, provider=$LLM_PROVIDER, bind=$BIND_HOST:$PORT)
  Rust       : $(command -v cargo >/dev/null 2>&1 && cargo --version | awk '{print $1,$2}' || echo '未安装')
  前端 dist  : $([ -d "$FRONTEND/dist" ] && echo "$FRONTEND/dist (就绪)" || echo "未就绪，需从 x86 拷入")
  受限账户   : $(id "$EXEC_USER" >/dev/null 2>&1 && echo "$EXEC_USER (已建)" || echo "未建（加 --systemd 自动建）")
  systemd    : $([ "$DO_SYSTEMD" -eq 1 ] && echo "已安装并自启" || echo "未安装")

  手工前台启动后端（未用 systemd 时）:
    cd $BACKEND && source .venv/bin/activate
    uvicorn app.main:app --host $BIND_HOST --port $PORT --loop asyncio --http h11

  冒烟：
    curl --noproxy '*' http://127.0.0.1:$PORT/health
    curl --noproxy '*' http://127.0.0.1:$PORT/tools
    python scripts/demo.py --provider mock --auto

  切到联网 DeepSeek：编辑 $BACKEND/.env 设 LLM_PROVIDER=deepseek + DEEPSEEK_API_KEY
${C_G}=====================================================${C_0}
SUMMARY
ok "全部完成。"