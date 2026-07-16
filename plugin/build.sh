#!/usr/bin/env bash
# Bundle the Decky plugin: copy the canonical Python crypto module in,
# build the frontend, zip the result for Decky's "install from zip".
set -euo pipefail
cd "$(dirname "$0")"

# py_modules/fmsd_crypto.py is the DEVICE implementation (ctypes ->
# libsodium) — do NOT overwrite it with the PyNaCl one from crypto/py.
# Bundle a libsodium built against old glibc so any SteamOS 3.x loads it.
if [ ! -f py_modules/libsodium.so ]; then
  for so in /lib/x86_64-linux-gnu/libsodium.so.23 /usr/lib/libsodium.so; do
    [ -f "$so" ] && cp "$so" py_modules/libsodium.so && break
  done
fi
[ -f py_modules/libsodium.so ] || echo "warn: no libsodium.so bundled — device will rely on system copy"

# Frontend (requires network for decky deps; see README)
if [ -d node_modules ]; then
  npx rollup -c
else
  echo "note: plugin/node_modules missing — run 'pnpm i' in plugin/ first (needs @decky/ui toolchain)"
fi

mkdir -p ../out
zip -qr ../out/findmydeck-plugin.zip plugin.json main.py py_modules dist package.json 2>/dev/null || \
  zip -qr ../out/findmydeck-plugin.zip plugin.json main.py py_modules package.json
echo "wrote out/findmydeck-plugin.zip"
