#!/usr/bin/env bash
set -euo pipefail

if ! command -v pacman >/dev/null 2>&1; then
  cat >&2 <<'EOF'
[!] This helper targets Arch Linux.
    On Debian/Ubuntu install: build-essential cmake libbluetooth-dev
    Then run: cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
              cmake --build build -j"$(nproc)"
EOF
  exit 1
fi

echo "[*] BlueBoy build dependencies (Arch)"
sudo pacman -S --needed --noconfirm base-devel cmake bluez bluez-libs

echo "[*] Configuring"
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release

echo "[*] Building"
cmake --build build -j"$(nproc)"

echo "[*] Running unit tests"
ctest --test-dir build --output-on-failure

echo "[+] Done -> ./build/blueboy"
echo "    The first run shows the consent disclaimer; read it before accepting."
