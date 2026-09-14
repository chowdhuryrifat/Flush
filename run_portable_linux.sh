#!/usr/bin/env bash
# ============================================================
#  Portable launcher for USB Shortcut Virus Remover (Linux)
#  Drop this ENTIRE folder on a USB stick; run this script.
#  Prefers the built binary, falls back to running from source.
# ============================================================
set -uo pipefail
cd "$(dirname "$0")"

BIN="dist/usb-virus-cleaner"

if [ -x "$BIN" ]; then
    exec "$BIN"
fi

if command -v python3 >/dev/null 2>&1; then
    if ! python3 -c "import tkinter" 2>/dev/null; then
        echo "[ERROR] tkinter not installed. Run: sudo apt install python3-tk"
        exit 1
    fi
    exec python3 usb_cleaner.py
fi

echo "[ERROR] Neither the built binary nor python3 is available."
echo "        Build the binary first with: ./build_linux.sh"
exit 1