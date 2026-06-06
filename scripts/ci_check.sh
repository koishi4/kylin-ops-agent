#!/usr/bin/env bash
# 一键可复现校验（P0-5）：装依赖 → 离线 mock 跑后端测试 → 构建前端。
# 目标：任何人 clone 后一条命令复现「测试全绿 + 前端可构建」，杜绝「只在我机器上能跑」。
#
# 用法：  bash scripts/ci_check.sh
# 约定：  后端测试默认 LLM_PROVIDER=mock —— 无需 key、无需联网、结果确定（不依赖云端模型）。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

echo "==> [1/4] 检查 Python 版本（要求 3.11）"
PY="${PYTHON:-python3.11}"
if ! command -v "$PY" >/dev/null 2>&1; then
  PY="python3"
fi
"$PY" --version

echo "==> [2/4] 后端：创建虚拟环境并安装依赖"
cd "$ROOT/backend"
if [ ! -d .venv ]; then
  "$PY" -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --quiet --upgrade pip
# 优先用锁定版本复现；无锁文件则退回 requirements.txt
if [ -f requirements.lock ]; then
  pip install --quiet -r requirements.lock
else
  pip install --quiet -r requirements.txt
fi

echo "==> [3/4] 后端：离线 mock 跑全部测试"
LLM_PROVIDER=mock PYTHONPATH=. python -m pytest -q

echo "==> [4/4] 前端：安装并构建"
cd "$ROOT/frontend"
if command -v npm >/dev/null 2>&1; then
  if [ -f package-lock.json ]; then
    npm ci --silent
  else
    npm install --silent
  fi
  npm run build
else
  echo "    （跳过：未检测到 npm；如需前端构建请安装 Node.js）"
fi

echo "==> 全部通过 ✓"
