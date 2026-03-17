#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ -f "$ROOT_DIR/.venv/bin/activate" ]]; then
  source "$ROOT_DIR/.venv/bin/activate"
fi

export SOFTHSM2_CONF="${SOFTHSM2_CONF:-$ROOT_DIR/conf/softhsm2.conf}"

if [[ -z "${SOFTHSM_MODULE:-}" ]]; then
  for p in     /usr/lib/softhsm/libsofthsm2.so     /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so     /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so; do
    if [[ -f "$p" ]]; then
      export SOFTHSM_MODULE="$p"
      break
    fi
  done
fi

echo "[*] SOFTHSM2_CONF=$SOFTHSM2_CONF"
echo "[*] SOFTHSM_MODULE=${SOFTHSM_MODULE:-<not set>}"
exec uvicorn app.main:app --host 127.0.0.1 --port 8000
