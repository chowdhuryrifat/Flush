#!/usr/bin/env bash
# ============================================================
#  USB Shortcut Virus Remover - Linux build script
#  Builds a standalone portable binary with PyInstaller
# ============================================================
set -euo pipefail
cd "$(dirname "$0")"

echo "=== USB Shortcut Virus Remover - Linux Build ==="

# 0. Check python3
if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] python3 not found. Install Python 3.9+ and retry."
    exit 1
fi

# 0b. Ensure tkinter available at build time
if ! python3 -c "import tkinter" 2>/dev/null; then
    echo "[ERROR] python3-tk is required to build. Try: sudo apt install python3-tk python3-pil"
    exit 1
fi

# 1. Install build deps
echo "[1/3] Installing build dependencies..."
python3 -m pip install --upgrade pip --quiet || true
if ! python3 -m pip install --quiet -r requirements.txt pyinstaller 2>/dev/null; then
    echo "    pip blocked (externally-managed env) -> retrying with --break-system-packages"
    python3 -m pip install --quiet --break-system-packages --upgrade pip || true
    python3 -m pip install --quiet --break-system-packages -r requirements.txt pyinstaller
fi

# 2. Build icon
echo "[2/3] Generating application icon..."
python3 build_icon.py

# 3. PyInstaller - one-file portable binary
echo "[3/3] Building portable executable with PyInstaller..."
python3 -m PyInstaller \
    --noconfirm \
    --onefile \
    --windowed \
    --name "usb-virus-cleaner" \
    --icon icon.png \
    --add-data "icon.png:." \
    --clean \
    --exclude-module PIL \
    usb_cleaner.py

echo ""
echo "=== BUILD COMPLETE ==="
echo "Portable executable: dist/usb-virus-cleaner"
echo "Run it: ./dist/usb-virus-cleaner"