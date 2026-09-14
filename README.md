# Flush — USB Shortcut Virus Remover

A lightweight, portable tool that scans USB/removable drives for the
"shortcut virus" (LNK worm), removes malicious files, and restores
hidden files. Ships as a single self-contained executable for Windows
and Linux — no Python install required.

![UI](icon.png)

## Features

- **Cross-platform** — one binary each for Windows and Linux (Python + Tkinter, packaged with PyInstaller)
- **Detects the shortcut virus** — `.lnk` files, `autorun.inf`, malicious scripts/VBS/exe/scr payloads
- **Restores hidden files** — un-hides legitimate files the virus hid
- **Pre-clean backup** — quarantine folder on your Desktop before removing anything
- **Scan report** — HTML/text summary of everything found
- **Auto-open on USB insert** — optional OS-level integration (Windows Task Scheduler / Linux udev rule)
- **Offline signature database** — portable virus-signature list, no cloud needed

## Download

Grab the latest binary from the [Releases](../../releases) page:

| Platform | File | Notes |
|----------|------|-------|
| Windows | `USB-Virus-Cleaner-Windows.exe` | Right-click → Run as administrator for auto-open integration |
| Linux | `usb-virus-cleaner` | `chmod +x` then run |

## Usage

1. Insert your USB drive.
2. Open Flush, pick the drive (or wait for the auto-open prompt).
3. Click **Scan** to detect threats.
4. Click **Clean & Fix** to remove them (a backup is created first).
5. Enable **Auto-open on USB insert** for auto-scanning future drives.

### Command line

```
./usb-virus-cleaner                     # normal GUI
./usb-virus-cleaner /media/USB          # open and prompt to scan that path
./usb-virus-cleaner /dev/sdb1           # open and prompt (resolves mount point)
./usb-virus-cleaner --autostart         # used by the OS auto-open trigger
```

## Building from source

Requires Python 3.8+ and PyInstaller.

### Linux

```bash
pip install pyinstaller pillow
./build_linux.sh
```

### Windows

```bat
pip install pyinstaller pillow
build_windows.bat
```

Output lands in `dist/` (Linux: `usb-virus-cleaner`, Windows: `USB Virus Cleaner.exe`).

## How auto-open works

- **Windows** — installs a Task Scheduler task triggered by the Kernel-PnP
  device event (`EventID 400` filtered to `USBSTOR`) via `schtasks`.
- **Linux** — installs a `udev` rule at `/etc/udev/rules.d/99-usb-cleaner-autorun.rules`
  that runs on any USB block partition (`ID_BUS=usb` + `ID_FS_USAGE=filesystem`),
  plus a wrapper at `/usr/local/bin/usb-cleaner-autostart.sh`.

Use the built-in toggle (Enable/Disable) in the app to manage this; it'll
prompt for elevation (UAC / `pkexec` / `sudo`) as needed.

## Disclaimer

This tool targets the common USB **shortcut/LNK worm**. It is not a
replacement for a full antivirus. Always back up important files.