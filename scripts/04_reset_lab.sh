#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[*] Deleting token TestToken (if exists)..."
SOFTHSM2_CONF="$ROOT_DIR/conf/softhsm2.conf" softhsm2-util --delete-token --token "TestToken" || true

echo "[*] Removing local state..."
rm -rf "$ROOT_DIR/softhsm_tokens" "$ROOT_DIR/conf" "$ROOT_DIR/state"
mkdir -p "$ROOT_DIR/state"

echo "[*] Re-initializing SoftHSM2..."
bash "$ROOT_DIR/scripts/02_init_softhsm.sh"
echo "[*] Done."
