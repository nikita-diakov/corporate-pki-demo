#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF_DIR="$ROOT_DIR/conf"
TOK_DIR="$ROOT_DIR/softhsm_tokens"

mkdir -p "$CONF_DIR" "$TOK_DIR"

cat > "$CONF_DIR/softhsm2.conf" <<EOF
directories.tokendir = $TOK_DIR
objectstore.backend = file
log.level = INFO
EOF

export SOFTHSM2_CONF="$CONF_DIR/softhsm2.conf"

echo "[*] SOFTHSM2_CONF=$SOFTHSM2_CONF"
echo "[*] Initializing token TestToken (SO PIN=1234, User PIN=1234)..."
softhsm2-util --init-token --free --label "TestToken" --so-pin 1234 --pin 1234

echo
echo "[*] Slots:"
softhsm2-util --show-slots
echo
echo "[*] Done."
