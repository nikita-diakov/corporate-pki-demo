#!/usr/bin/env bash
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONF="$ROOT_DIR/conf/softhsm2.conf"
PIN="${TOKEN_PIN:-1234}"

MOD="${SOFTHSM_MODULE:-}"
if [[ -z "$MOD" ]]; then
  for p in     /usr/lib/softhsm/libsofthsm2.so     /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so     /usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so; do
    [[ -f "$p" ]] && MOD="$p" && break
  done
fi

export SOFTHSM2_CONF="$CONF"
echo "[*] SOFTHSM2_CONF=$SOFTHSM2_CONF"
echo "[*] module=${MOD:-<not found>}"
echo

softhsm2-util --show-slots || true
echo

if [[ -z "$MOD" ]]; then
  echo "[-] libsofthsm2.so not found"
  exit 1
fi

echo "[*] List objects:"
pkcs11-tool --module "$MOD" --login --pin "$PIN" --list-objects || true
echo

echo "[*] Test key generation via pkcs11-tool:"
pkcs11-tool --module "$MOD" --login --pin "$PIN"   --keypairgen --key-type rsa:2048 --label diagKey --id 0a

echo "[+] OK"
