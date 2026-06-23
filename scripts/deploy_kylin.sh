#!/usr/bin/env bash
# =============================================================================
# 麒麟虚机一键部署脚本（软件杯 A2：麒麟安全智能运维 Agent）
# -----------------------------------------------------------------------------
# 目标环境：麒麟高级服务器操作系统 V11 + LoongArch（loongarch64），官方发放虚机。
#   也兼容其它 RPM(dnf/yum) / Debian(apt) 发行版与 x86_64（自动探测，便于本机预演）。
#
# 一条命令完成：① 装系统依赖 → ② 从 GitHub 拉代码 → ③ 建后端 venv 装 Python 依赖
#              → ④ 写 .env 配置 → ⑤ 处理前端 dist → ⑥ （可选）建 opsagent 账户 + systemd
#              → ⑦ 冒烟自检（/health、/tools）。脚本【幂等】，可反复运行。
#
# 设计依据：docs/deploy-loongarch.md（本脚本是该预案的可执行落地版）。核心适配点：
#   - venv 用 --system-site-packages，让系统包提供的 psutil(C)/pydantic(Rust) 直接可见，
#     避免在 LoongArch 上源码编译这两个扩展（最大迁移成本）。
#   - 安装 uvicorn 时【去掉 [standard]】（uvloop/httptools/watchfiles 是编译大头且非必需），
#     启动加 --loop asyncio --http h11，功能不受影响。
#   - 前端不在 LoongArch 构建：仓库已带 frontend/dist/；若本机有 npm 才尝试重建。
#   - LLM 默认 mock（完全离线、断网可演示）；要联网用 --provider deepseek --api-key sk-xxx。
#   - 最小权限（赛题需求④）：--systemd 会建非登录的 opsagent 账户并以其身份跑后端。
#
# 用法：
#   bash scripts/deploy_kylin.sh                      # 默认：拉代码到 /opt、mock 离线、不建服务
#   bash scripts/deploy_kylin.sh --systemd            # 额外建 opsagent + systemd 开机自启（推荐）
#   bash scripts/deploy_kylin.sh --provider deepseek --api-key sk-xxx
#   bash scripts/deploy_kylin.sh --dir /srv/kylin --branch main --bind 0.0.0.0 --systemd
#   bash scripts/deploy_kylin.sh --help
#
# 退出码：0 成功；非 0 见对应步骤报错。
# =============================================================================
set -euo pipefail

# ---------- 可配置默认值（命令行参数可覆盖） ----------
REPO_URL="https://github.com/koishi4/kylin-ops-agent.git"
BRANCH="main"
INSTALL_DIR="/opt/kylin-ops-agent"
LLM_PROVIDER="mock"          # mock=离线确定性桩（默认，断网可演示）；deepseek=云端国产开源
DEEPSEEK_API_KEY=""          # provider=deepseek 时必填
BIND_HOST="127.0.0.1"        # 后端监听地址；默认只回环（最安全）。对外暴露用 0.0.0.0（须配 token）
PORT="8000"
EXEC_USER="opsagent"         # 最小权限运维账户（与 backend/.env 默认 EXEC_USER 一致）
DO_SYSTEMD=0                 # 1=建 opsagent 账户 + 安装并启用 systemd 服务
DO_NGINX=0                   # 1=用 nginx 托管前端 dist 并反代 /api → 后端
SKIP_TESTS=0                 # 1=跳过 pytest 回归（默认跑，最能证明适配成功）
SKIP_SYSDEPS=0              # 1=跳过 dnf/apt 装系统依赖（无 sudo 或已手工装好时用）

# ---------- 彩色日志 ----------
if [ -t 1 ]; then C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_B=$'\033[36m'; C_0=$'\033[0m'
else C_G=; C_Y=; C_R=; C_B=; C_0=; fi
log()  { printf '%s==>%s %s\n' "$C_B" "$C_0" "$*"; }
ok()   { printf '%s ✓ %s%s\n' "$C_G" "$*" "$C_0"; }
warn() { printf '%s ! %s%s\n' "$C_Y" "$*" "$C_0" >&2; }
die()  { printf '%s ✗ %s%s\n' "$C_R" "$*" "$C_0" >&2; exit 1; }

usage() {
  # 打印脚本顶部连续的注释头（到第一行非注释为止），剥掉前导 '# '。
  awk 'NR==1{next} /^#/{sub(/^# ?/,"");print;next} {exit}' "$0"
  exit 0
}

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
    -h|--help)    usage ;;
    *) die "未知参数：$1（用 --help 看用法）" ;;
  esac
done

# ---------- sudo 包装（非 root 时自动加 sudo；root 直接执行） ----------
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
[ "$ARCH" = "loongarch64" ] && ok "LoongArch 目标架构，按预案走系统包优先策略" \
  || warn "非 loongarch64（$ARCH）：脚本仍可用（多为本机预演），LoongArch 专属适配点会自动跳过。"

# 选包管理器
PKG=""
if   command -v dnf >/dev/null 2>&1; then PKG="dnf"
elif command -v yum >/dev/null 2>&1; then PKG="yum"
elif command -v apt-get >/dev/null 2>&1; then PKG="apt"
fi
[ -n "$PKG" ] && printf '    包管理器: %s\n' "$PKG" || warn "未识别包管理器，将跳过系统依赖安装。"

# ---------- 1. 安装系统依赖 ----------
log "[1/8] 安装系统依赖（Python/编译链/系统采集工具）"
if [ "$SKIP_SYSDEPS" -eq 1 ] || [ -z "$PKG" ]; then
  warn "跳过系统依赖安装（--skip-sysdeps 或无包管理器）。请自行确保 python3(>=3.11)/gcc/lsof/ss 等就绪。"
else
  case "$PKG" in
    dnf|yum)
      # 系统包优先提供 psutil(C)/pydantic(Rust)，省去 LoongArch 上源码编译；
      # git/gcc/make/python3-devel 为兜底编译链；lsof/iproute/procps-ng 为 OS 采集工具。
      $SUDO "$PKG" install -y \
        git python3 python3-pip python3-devel gcc gcc-c++ make \
        python3-psutil python3-pyyaml \
        sqlite lsof iproute procps-ng \
        || warn "部分系统包安装失败（可能源中无此包名）：稍后用 pip 兜底，必要时见 docs/deploy-loongarch.md §2。"
      # pydantic 系统包名各发行版不一，单独尝试（失败则后续走 venv/pip 编译）
      $SUDO "$PKG" install -y python3-pydantic 2>/dev/null \
        || warn "无 python3-pydantic 系统包：将由 venv 内 pip 处理（LoongArch 上可能触发 Rust 编译，需 rust/cargo）。"
      ;;
    apt)
      $SUDO apt-get update -y || true
      $SUDO apt-get install -y \
        git python3 python3-venv python3-pip python3-dev build-essential \
        python3-psutil python3-yaml \
        sqlite3 lsof iproute2 procps \
        || warn "部分 apt 包安装失败，pip 兜底。"
      ;;
  esac
  ok "系统依赖处理完成"
fi

# 选 Python 解释器（优先 3.11，符合可复现硬约束；否则退回 python3 并告警）
PY=""
for c in python3.11 python3; do
  if command -v "$c" >/dev/null 2>&1; then PY="$c"; break; fi
done
[ -n "$PY" ] || die "未找到 python3，请先安装 Python 3.11。"
PYVER="$("$PY" -c 'import sys;print("%d.%d"%sys.version_info[:2])')"
printf '    Python: %s (%s)\n' "$PYVER" "$("$PY" -c 'import sys;print(sys.executable)')"
case "$PYVER" in
  3.11|3.12|3.13) ok "Python 版本满足（>=3.11）" ;;
  3.10) warn "Python 3.10：项目用到 3.10+ 的 X|Y 类型标注，应能跑；建议升 3.11。" ;;
  *) warn "Python $PYVER 低于 3.11，可能有语法不兼容（见 docs/deploy-loongarch.md §5）。" ;;
esac

# 校验 OS 采集工具是否就位（项目封装这些原生命令）
for t in lsof ss journalctl df free ps; do
  command -v "$t" >/dev/null 2>&1 && printf '    [tool] %-10s ✓\n' "$t" \
    || warn "缺少 $t：相关 MCP 感知工具可能降级（非致命）。"
done

# ---------- 2. 从 GitHub 拉代码 ----------
log "[2/8] 拉取代码：$REPO_URL ($BRANCH) → $INSTALL_DIR"
PARENT_DIR="$(dirname "$INSTALL_DIR")"
$SUDO mkdir -p "$PARENT_DIR"
# 若安装目录父级不可写（如 /opt 归 root），后续 git/写文件用 $SUDO 兜底。
if [ -d "$INSTALL_DIR/.git" ]; then
  log "已存在仓库，执行更新（fetch + reset 到 origin/$BRANCH）"
  $SUDO git -C "$INSTALL_DIR" remote set-url origin "$REPO_URL"
  $SUDO git -C "$INSTALL_DIR" fetch --depth 1 origin "$BRANCH"
  $SUDO git -C "$INSTALL_DIR" checkout -B "$BRANCH" "origin/$BRANCH"
  $SUDO git -C "$INSTALL_DIR" reset --hard "origin/$BRANCH"
else
  [ -e "$INSTALL_DIR" ] && [ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ] \
    && die "$INSTALL_DIR 已存在且非 git 仓库且非空，请清理或换 --dir。"
  $SUDO git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR"
fi
# 让当前用户拥有目录（便于后续非 sudo 写 venv/.env）；systemd 步骤会再交给 opsagent。
[ -n "$SUDO" ] && $SUDO chown -R "$(id -u):$(id -g)" "$INSTALL_DIR" || true
ok "代码就位：$(git -C "$INSTALL_DIR" rev-parse --short HEAD) $(git -C "$INSTALL_DIR" log -1 --pretty=%s | cut -c1-50)"

BACKEND="$INSTALL_DIR/backend"
FRONTEND="$INSTALL_DIR/frontend"
[ -d "$BACKEND" ] || die "未找到 backend/ 目录，仓库结构异常。"

# ---------- 3. 后端 venv + Python 依赖 ----------
log "[3/8] 创建后端虚拟环境并安装 Python 依赖"
cd "$BACKEND"
# --system-site-packages：让系统包的 psutil/pydantic 对 venv 可见，避免 LoongArch 上源码编译。
[ -d .venv ] || "$PY" -m venv --system-site-packages .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip >/dev/null

# 由 requirements.txt 动态生成 LoongArch 友好的安装清单：
#   1) uvicorn[standard] → uvicorn（去掉 uvloop/httptools/watchfiles 等编译大头）
#   2) 保留其余纯 Python 依赖原样；psutil/pydantic 若系统包已满足版本，pip 会因 --system-site-packages 跳过。
REQ_SRC="requirements.txt"; [ -f "$REQ_SRC" ] || die "缺少 backend/requirements.txt"
REQ_TMP="$(mktemp)"; trap 'rm -f "$REQ_TMP"' EXIT
sed -E 's/uvicorn\[[^]]*\]/uvicorn/' "$REQ_SRC" > "$REQ_TMP"

log "安装依赖（可能触发少量源码编译，请耐心等待）"
if ! pip install -r "$REQ_TMP"; then
  warn "整体安装有失败项，逐行重试以定位（psutil/pydantic 编译失败见 docs/deploy-loongarch.md §2 策略 B）。"
  while IFS= read -r line; do
    case "$line" in ''|\#*) continue ;; esac
    pkg="${line%%#*}"; pkg="$(echo "$pkg" | xargs)"
    [ -z "$pkg" ] && continue
    pip install "$pkg" || warn "依赖安装失败：$pkg（继续，稍后冒烟检验）"
  done < "$REQ_TMP"
fi

# 关键扩展可导入性自检：psutil/pydantic 任一缺失则明确报错并给修复指引。
python - <<'PYCHK' || die "关键依赖导入失败，请按上方提示处理（多为 psutil/pydantic 在 LoongArch 上需系统包或编译链）。"
import importlib, sys
need = ["fastapi", "uvicorn", "psutil", "pydantic", "yaml", "mcp", "httpx", "aiosqlite", "bashlex"]
miss = []
for m in need:
    try: importlib.import_module(m)
    except Exception as e: miss.append(f"{m} ({e.__class__.__name__})")
if miss:
    print("  缺失/不可导入: " + ", ".join(miss)); sys.exit(1)
import psutil, pydantic
print(f"  deps ok  psutil={psutil.__version__}  pydantic={pydantic.VERSION}")
PYCHK
ok "后端依赖就绪"

# ---------- 4. 写 .env 配置 ----------
log "[4/8] 写后端 .env 配置（provider=$LLM_PROVIDER, bind=$BIND_HOST）"
if [ ! -f .env ]; then cp .env.example .env; fi
# 用小工具就地改键（存在则改、不存在则追加），避免重复行。
set_env() { # set_env KEY VALUE
  local k="$1" v="$2"
  if grep -qE "^${k}=" .env; then
    sed -i -E "s|^${k}=.*|${k}=${v}|" .env
  else
    printf '%s=%s\n' "$k" "$v" >> .env
  fi
}
set_env LLM_PROVIDER "$LLM_PROVIDER"
set_env API_BIND_HOST "$BIND_HOST"
set_env EXEC_USER "$EXEC_USER"
if [ "$LLM_PROVIDER" = "deepseek" ]; then
  if [ -n "$DEEPSEEK_API_KEY" ]; then
    set_env DEEPSEEK_API_KEY "$DEEPSEEK_API_KEY"
  else
    warn "provider=deepseek 但未给 --api-key：请手工在 $BACKEND/.env 填 DEEPSEEK_API_KEY，否则联网调用会失败。"
  fi
fi
# 非回环绑定（联网/生产）触发失败安全守卫：必须有 OPERATOR_TOKEN + 非默认 AUDIT_HMAC_KEY，否则后端拒绝启动。
case "$BIND_HOST" in
  127.0.0.1|localhost|::1) : ;;  # 回环：演示模式，不强制
  *)
    if grep -qE '^OPERATOR_TOKEN=(please-change-me)?$' .env; then
      TOK="$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
      set_env OPERATOR_TOKEN "$TOK"
      warn "检测到对外绑定（$BIND_HOST）：已自动生成 OPERATOR_TOKEN（见 .env）；前端 VITE_OPERATOR_TOKEN 需设同值。"
    fi
    if grep -qE '^AUDIT_HMAC_KEY=kylin-ops-agent-audit-chain-v1$' .env; then
      set_env AUDIT_HMAC_KEY "kylin-$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
      warn "已为对外部署生成独立 AUDIT_HMAC_KEY（审计哈希链密钥）。"
    fi
    ;;
esac
ok ".env 配置完成：$BACKEND/.env"

# ---------- 5. 前端 dist ----------
log "[5/8] 处理前端静态产物"
if [ -d "$FRONTEND/dist" ] && [ -n "$(ls -A "$FRONTEND/dist" 2>/dev/null)" ]; then
  ok "仓库已带 frontend/dist（按预案：不在 LoongArch 上构建，直接托管）。"
elif command -v npm >/dev/null 2>&1; then
  warn "未见 dist 但检测到 npm：尝试本机构建（注意：LoongArch 上构建非推荐路径）。"
  ( cd "$FRONTEND" && (npm ci --silent || npm install --silent) && npm run build ) \
    && ok "前端构建完成 → frontend/dist" \
    || warn "前端构建失败：请在 x86 开发机 npm run build 后把 dist/ 拷过来（docs/deploy-loongarch.md §1/§3）。"
else
  warn "无 dist 且无 npm：请在 x86 开发机构建后将 frontend/dist 拷到 $FRONTEND/（不在 LoongArch 构建前端）。"
fi

# ---------- 6. 最小权限账户 + systemd（可选） ----------
log "[6/8] 最小权限账户 + systemd 服务"
if [ "$DO_SYSTEMD" -eq 1 ]; then
  [ -n "$SUDO" ] || [ "$(id -u)" -eq 0 ] || die "--systemd 需要 root/sudo。"
  # ① 建非登录的受限运维账户（赛题需求④：核心动作在受限 Account 下运行）
  if ! id "$EXEC_USER" >/dev/null 2>&1; then
    $SUDO useradd -r -s /usr/sbin/nologin "$EXEC_USER" 2>/dev/null \
      || $SUDO useradd -r -s /sbin/nologin "$EXEC_USER" \
      || warn "创建 $EXEC_USER 账户失败（可能已存在或 nologin 路径不同）。"
    id "$EXEC_USER" >/dev/null 2>&1 && ok "已创建受限账户 $EXEC_USER"
  else
    ok "受限账户 $EXEC_USER 已存在"
  fi
  $SUDO chown -R "$EXEC_USER":"$EXEC_USER" "$INSTALL_DIR"

  # ② 安装 systemd 服务，以 opsagent 身份跑（直接坐实「非必要不 root」）
  UNIT=/etc/systemd/system/kylin-ops-agent.service
  $SUDO tee "$UNIT" >/dev/null <<UNITEOF
[Unit]
Description=Kylin Ops Agent (软件杯 A2 安全智能运维 Agent)
After=network.target

[Service]
User=$EXEC_USER
Group=$EXEC_USER
WorkingDirectory=$BACKEND
# 去 [standard] 的纯 Python 事件循环，LoongArch 友好
ExecStart=$BACKEND/.venv/bin/uvicorn app.main:app --host $BIND_HOST --port $PORT --loop asyncio --http h11
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes

[Install]
WantedBy=multi-user.target
UNITEOF
  $SUDO systemctl daemon-reload
  $SUDO systemctl enable --now kylin-ops-agent
  ok "systemd 服务已安装并启动（开机自启）：systemctl status kylin-ops-agent"
else
  warn "未加 --systemd：跳过 opsagent 账户与开机自启服务。可手工前台启动（见末尾提示）。"
fi

# ---------- 6.5 nginx 托管前端（可选） ----------
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
      || warn "nginx 配置校验/重载失败，请检查 $NGX。"
  else
    warn "未能安装 nginx，跳过。前端可用 vite 开发服务器或自行托管 dist。"
  fi
fi

# ---------- 7. 冒烟自检 ----------
log "[7/8] 冒烟自检（离线 mock 跑测试 + 起服务探活）"
cd "$BACKEND"
if [ "$SKIP_TESTS" -eq 1 ]; then
  warn "按 --skip-tests 跳过 pytest 回归。"
else
  log "pytest 全套回归（LLM_PROVIDER=mock，离线确定）"
  if LLM_PROVIDER=mock PYTHONPATH=. python -m pytest -q; then
    ok "pytest 全绿（这是 LoongArch 适配成功最硬的证据）。"
  else
    warn "pytest 有未通过项：root/容器环境有两处已知差异（kill 授权、沙箱内存归因），其余请核查。"
  fi
fi

# 探活：systemd 已起则直接探；否则临时拉起一个进程探活后关掉。
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
  ok "/tools   → 列出 $TOOLS_N 个 MCP 工具（评分① 列工具）"
else
  warn "探活失败：看日志 /tmp/kylin-ops-smoke.log 或 journalctl -u kylin-ops-agent。"
fi
# 关掉临时探活进程（systemd 模式不动）
[ -n "${SMOKE_PID:-}" ] && kill "$SMOKE_PID" >/dev/null 2>&1 || true

# ---------- 8. 收尾提示 ----------
log "[8/8] 部署完成"
cat <<SUMMARY

${C_G}====================== 部署摘要 ======================${C_0}
  代码目录   : $INSTALL_DIR  ($(git -C "$INSTALL_DIR" rev-parse --short HEAD))
  后端       : $BACKEND  (venv: .venv, provider=$LLM_PROVIDER, bind=$BIND_HOST:$PORT)
  前端 dist  : $([ -d "$FRONTEND/dist" ] && echo "$FRONTEND/dist (就绪)" || echo "未就绪，需从 x86 拷入")
  受限账户   : $(id "$EXEC_USER" >/dev/null 2>&1 && echo "$EXEC_USER (已建)" || echo "未建（加 --systemd 自动建）")
  systemd    : $([ "$DO_SYSTEMD" -eq 1 ] && echo "已安装并自启 (systemctl status kylin-ops-agent)" || echo "未安装")

  手工前台启动后端（未用 systemd 时）:
    cd $BACKEND && source .venv/bin/activate
    uvicorn app.main:app --host $BIND_HOST --port $PORT --loop asyncio --http h11

  冒烟：
    curl --noproxy '*' http://127.0.0.1:$PORT/health
    curl --noproxy '*' http://127.0.0.1:$PORT/tools
    python scripts/demo.py --provider mock --auto      # 一键剧本离线自检

  切到联网 DeepSeek：编辑 $BACKEND/.env 设 LLM_PROVIDER=deepseek + DEEPSEEK_API_KEY
${C_G}=====================================================${C_0}
SUMMARY
ok "全部完成。"
