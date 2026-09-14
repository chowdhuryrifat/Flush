#!/usr/bin/env python3
"""
USB Shortcut Virus Remover
--------------------------
Detects and cleans shortcut viruses from USB drives.
Cross-platform: Windows & Linux.
"""

import os
import sys
import shutil
import shlex
import stat
import platform
import subprocess
import threading
import time
import tempfile
from datetime import datetime
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except ImportError:
    print("tkinter is required. Install it with: sudo apt install python3-tk")
    sys.exit(1)

# ──────────────────────────────────────────────
# Embedded Autorun Resources
# Everything the app needs to install/uninstall its
# own "open on USB insert" trigger lives in these
# constants, so one binary is fully self-contained.
# ──────────────────────────────────────────────
# Windows: Task Scheduler XML (triggered by Kernel-PnP Event 400,
# filtered to USB storage so mice/keyboards don't open the app).
TASK_XML_TEMPLATE = """<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Opens the USB Shortcut Virus Remover whenever a USB drive is inserted.</Description>
  </RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Enabled>true</Enabled>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-Kernel-PnP/Configuration"&gt;&lt;Select Path="Microsoft-Windows-Kernel-PnP/Configuration"&gt;*[System[Provider[@Name='Microsoft-Windows-Kernel-PnP'] and (EventID=400)]] and *[EventData[Data contains 'USBSTOR']]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>true</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT2H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>__EXE_PATH__</Command>
      <Arguments>--autostart</Arguments>
    </Exec>
  </Actions>
</Task>"""

# Linux: udev rule installed to /etc/udev/rules.d/
# Matches ANY USB-attached block partition (ID_BUS=usb), regardless of which
# letter the kernel assigned (sda, sdb, ...). The KERNEL name is NOT reliable:
# on systems with NVMe internal disks the USB stick ends up as "sda".
UDEV_RULE = (
    '# Autorun the USB cleaner when any USB block partition appears.\n'
    'ACTION=="add", SUBSYSTEM=="block", DEVTYPE=="partition", '
    'ENV{ID_BUS}=="usb", ENV{ID_FS_USAGE}=="filesystem", '
    'RUN+="/usr/local/bin/usb-cleaner-autostart.sh $env{DEVNAME}"\n'
)

# Linux: wrapper script installed to /usr/local/bin/. Contains {APP} placeholder
# replaced with the current executable path at install time.
WRAPPER_SCRIPT = r"""#!/usr/bin/env bash
set -uo pipefail
APP="__APP_PATH__"
case "$APP" in
    *" "*) ;;   # multi-word command (e.g. python3 .../usb_cleaner.py) -> skip -x check
    *) [ -x "$APP" ] || exit 0 ;;
esac
[ -z "$1" ] && exit 0
DEVICE="$1"
[ ! -e "$DEVICE" ] && [ -e "/dev/$1" ] && DEVICE="/dev/$1"
MOUNT=""
for i in $(seq 1 12); do
    if command -v lsblk >/dev/null 2>&1 && lsblk -rno MOUNTPOINT "$DEVICE" | grep -q "/"; then
        MOUNT="$(lsblk -rno MOUNTPOINT "$DEVICE" | grep "^/" | head -1)"
        break
    fi
    sleep 0.5
done
ACTIVE_USER=""
DISPLAY_VALUE=""
XAUTH_VALUE=""
if command -v loginctl >/dev/null 2>&1; then
    ACTIVE_USER="$(loginctl list-sessions --no-legend 2>/dev/null | awk '$4 == "seat0" && tolower($6) == "active" {print $3; exit}')"
    [ -z "$ACTIVE_USER" ] && ACTIVE_USER="$(loginctl list-sessions --no-legend 2>/dev/null | awk '$4 == "seat0" {print $3; exit}')"
    [ -z "$ACTIVE_USER" ] && ACTIVE_USER="$(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $3; exit}')"
fi
[ -z "$ACTIVE_USER" ] && ACTIVE_USER="$(awk -F: '$3>=1000 && $3<65534 {print $1; exit}' /etc/passwd)"
[ -z "$ACTIVE_USER" ] && ACTIVE_USER="${SUDO_USER:-root}"
for d in /tmp/.X11-unix/X*; do
    [ -e "$d" ] || continue
    DISPLAY_VALUE=":$(basename "$d" | tr -dc '0-9')"
    break
done
[ -z "$DISPLAY_VALUE" ] && DISPLAY_VALUE=":0"
if [ "$ACTIVE_USER" != "root" ]; then
    for xa in "/home/$ACTIVE_USER/.Xauthority" "/home/$ACTIVE_USER/.xauth"; do
        [ -f "$xa" ] && XAUTH_VALUE="$xa" && break
    done
fi
export DISPLAY="$DISPLAY_VALUE"
[ -n "$XAUTH_VALUE" ] && export XAUTHORITY="$XAUTH_VALUE"
if [ -n "$MOUNT" ]; then
    if command -v runuser >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
        runuser -u "$ACTIVE_USER" -- env DISPLAY="$DISPLAY_VALUE" XAUTHORITY="$XAUTH_VALUE" nohup sh -c "$APP \"$MOUNT\"" >/dev/null 2>&1 &
    else
        nohup sh -c "$APP \"$MOUNT\"" >/dev/null 2>&1 &
    fi
else
    if command -v runuser >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
        runuser -u "$ACTIVE_USER" -- env DISPLAY="$DISPLAY_VALUE" XAUTHORITY="$XAUTH_VALUE" nohup sh -c "$APP --autostart" >/dev/null 2>&1 &
    else
        nohup sh -c "$APP --autostart" >/dev/null 2>&1 &
    fi
fi
logger -t usb-cleaner "Launched USB cleaner ($APP) for $DEVICE @ $MOUNT as $ACTIVE_USER"
exit 0
"""

# Linux: managed locations
LINUX_RULE_FILE = "/etc/udev/rules.d/99-usb-cleaner-autorun.rules"
LINUX_WRAPPER_FILE = "/usr/local/bin/usb-cleaner-autostart.sh"
LINUX_WRAPPER_LINK = "/usr/local/bin/usb-virus-cleaner"

# Windows: managed task name
WIN_TASK_NAME = "USB Cleaner Autorun"


# ──────────────────────────────────────────────
# Virus Signature Database
# ──────────────────────────────────────────────
KNOWN_MALICIOUS_PATTERNS = {
    "filenames": {
        "*.lnk": "Windows Shortcut File",
        "autorun.inf": "Autorun Configuration",
        "*.vbs": "VBScript Dropper",
        "*.vbe": "Encoded VBScript",
        "*.bat": "Batch File Dropper",
        "*.cmd": "CMD Script Dropper",
        "*.wsf": "Windows Script File",
        "*.ps1": "PowerShell Script",
    },
    "suspicious_folders": {
        "RECYCLER": "Suspicious Recycler Folder",
        "RECYCLED": "Suspicious Recycled Folder",
        "System Volume Information": "Suspicious SVI (often abused)",
        "msocache": "Suspicious MSO Cache",
        ".trash": "Hidden Trash Folder",
    },
}


# ──────────────────────────────────────────────
# Drive Detection
# ──────────────────────────────────────────────
def get_removable_drives():
    """Detect removable drives across Windows and Linux."""
    drives = []
    system = platform.system()

    if system == "Windows":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            drives_bitmask = kernel32.GetLogicalDrives()
            for i in range(26):
                if drives_bitmask & (1 << i):
                    drive_letter = chr(65 + i) + ":\\"
                    drive_type = kernel32.GetDriveTypeW(drive_letter)
                    # DRIVE_REMOVABLE = 2
                    if drive_type == 2:
                        try:
                            volume_name = ctypes.create_unicode_buffer(256)
                            kernel32.GetVolumeInformationW(
                                drive_letter, volume_name, 256,
                                None, None, None, None, 0
                            )
                            label = volume_name.value or drive_letter
                        except Exception:
                            label = drive_letter
                        drives.append({"path": drive_letter, "label": f"{label} ({drive_letter})"})
        except Exception as e:
            print(f"Windows drive detection error: {e}")

    elif system == "Linux":
        drives = _detect_linux_drives()

    return drives


def _detect_linux_drives():
    """Detect removable (USB) drives on Linux.

    Prefers `lsblk` (fast, shows transport + labels). Falls back to a
    recursive walk of common media directories when lsblk is unavailable.
    """
    # ── Method 1: lsblk ──
    for cmd in (["lsblk", "-rno", "NAME,LABEL,MOUNTPOINT,TRAN"],
                ["lsblk", "-rno", "NAME,LABEL,MOUNTPOINT"]):
        try:
            output = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=10, check=False
            ).stdout
            if not output.strip():
                continue

            drives = []
            for line in output.splitlines():
                parts = line.split()
                if len(parts) < 3:
                    continue
                name, label, mountpoint = parts[:3]
                transport = parts[3] if len(parts) > 3 else "usb"

                if mountpoint in ("", "/", "[SWAP]"):
                    continue
                # Only treat USB transports as removable when TRAN available.
                if transport != "usb":
                    continue
                if not os.path.isdir(mountpoint):
                    continue

                label = label or name or os.path.basename(mountpoint)
                drives.append({"path": mountpoint, "label": f"{label} ({mountpoint})"})

            if drives:
                return _dedupe_drives(drives)
        except (subprocess.SubprocessError, OSError):
            continue

    # ── Method 2: recursive walk of media dirs ──
    drives = []
    for base in ("/media", "/mnt", "/run/media"):
        if os.path.isdir(base):
            for root, dirs, files in os.walk(base):
                # Don't descend into huge trees; media dirs are shallow.
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                if os.path.ismount(root) and root != base:
                    label = os.path.basename(root)
                    drives.append({"path": root, "label": f"{label} ({root})"})
                    dirs[:] = []
                if root.count(os.sep) - base.count(os.sep) > 3:
                    dirs[:] = []

    return _dedupe_drives(drives)


def _dedupe_drives(drives):
    """Remove duplicate mount points while preserving order."""
    seen = set()
    unique = []
    for d in drives:
        if d["path"] not in seen:
            seen.add(d["path"])
            unique.append(d)
    return unique


# ──────────────────────────────────────────────
# Drive Watcher (Auto-scan on insert)
# ──────────────────────────────────────────────
class DriveWatcher:
    """Polls for newly inserted USB drives every `interval` seconds."""

    def __init__(self, on_new_drive, interval=2.0):
        self.on_new_drive = on_new_drive
        self.interval = interval
        self._known_drives = set()
        self._stop = threading.Event()
        self._thread = None

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._known_drives = {d["path"] for d in get_removable_drives()}
        self._stop.clear()
        self._thread = threading.Thread(target=self._poll, daemon=True,
                                        name="drive-watcher")
        self._thread.start()

    def stop(self):
        self._stop.set()

    def _poll(self):
        while not self._stop.is_set():
            time.sleep(self.interval)
            try:
                current = {d["path"] for d in get_removable_drives()}
            except Exception:
                continue
            previous = self._known_drives
            new_drives = current - previous
            removed_drives = previous - current
            self._known_drives = current
            for drive in new_drives:
                label = os.path.basename(drive.rstrip("/\\")) or drive
                self.on_new_drive(drive, label)
            for drive in removed_drives:
                self.on_new_drive(drive, "", removed=True)


# ──────────────────────────────────────────────
# Autorun Engine (install/uninstall OS-level
# "open on USB insert" trigger from within the app)
# ──────────────────────────────────────────────
def app_launch_command():
    """Return a fully-quoted shell command that launches this app.

    When frozen (PyInstaller) it's the exe path; otherwise python + script.
    """
    if getattr(sys, "frozen", False):
        return shlex.quote(sys.executable)
    return f"{shlex.quote(sys.executable)} {shlex.quote(os.path.abspath(__file__))}"


def autorun_status():
    """Return (enabled: bool, detail: str) describing current autorun state."""
    if platform.system() == "Windows":
        r = subprocess.run(["schtasks", "/Query", "/TN", WIN_TASK_NAME],
                           capture_output=True, text=True)
        if r.returncode == 0:
            return True, f"Task '{WIN_TASK_NAME}' is registered"
        return False, "No autorun task found"
    else:
        try:
            exists = os.path.isfile(LINUX_RULE_FILE) and os.path.isfile(LINUX_WRAPPER_FILE)
        except OSError:
            exists = False
        if exists:
            detail = "udev rule installed (runs on any USB insert)"
            try:
                with open(LINUX_RULE_FILE) as f:
                    if "# USB Cleaner" not in f.read():
                        detail = "udev rule present but not managed by this app"
            except OSError:
                pass
            return True, detail
        return False, "No udev rule installed"


def install_autorun():
    """Install the OS-level autorun trigger. Returns (ok, message)."""
    system = platform.system()
    if system == "Windows":
        return _install_autorun_windows()
    return _install_autorun_linux()


def uninstall_autorun():
    """Remove the OS-level autorun trigger. Returns (ok, message)."""
    system = platform.system()
    if system == "Windows":
        return _uninstall_autorun_windows()
    return _uninstall_autorun_linux()


def _install_autorun_windows():
    exe = app_launch_command()
    xml = TASK_XML_TEMPLATE.replace("__EXE_PATH__", exe.replace("\\", "\\\\"))
    tmp = os.path.join(tempfile.gettempdir(), "usb-cleaner-task.xml")
    try:
        with open(tmp, "w", encoding="utf-16") as f:
            f.write(xml)
    except OSError as e:
        return False, f"Cannot write task file: {e}"
    cmd = ["schtasks", "/Create", "/TN", WIN_TASK_NAME, "/XML", tmp, "/F"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as e:
        return False, f"Failed to run schtasks: {e}"
    os.remove(tmp)
    if r.returncode == 0:
        return True, "Autorun installed. Insert a USB drive to test it."
    # Common failure: not elevated. Try elevated re-run via PowerShell.
    try:
        ps = (
            "Start-Process -FilePath schtasks -ArgumentList "
            f"'/Create','/TN','{WIN_TASK_NAME}','/XML','{tmp}','/F' "
            "-Verb RunAs -Wait"
        )
        # Rewrite tmp since we removed it
        with open(tmp, "w", encoding="utf-16") as f:
            f.write(xml)
        r2 = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                            capture_output=True, text=True, timeout=120)
        os.remove(tmp)
        if r2.returncode == 0 or "SUCCESS" in r2.stdout.upper() or "成功" in r2.stdout:
            return True, "Autorun installed via elevated prompt."
    except Exception as e:
        pass
    return False, f"schtasks failed ({r.returncode}):\n{r.stderr.strip()}"


def _uninstall_autorun_windows():
    cmd = ["schtasks", "/Delete", "/TN", WIN_TASK_NAME, "/F"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as e:
        return False, f"Failed to run schtasks: {e}"
    if r.returncode == 0:
        return True, "Autorun removed."
    try:
        ps = (
            "Start-Process -FilePath schtasks -ArgumentList "
            f"'/Delete','/TN','{WIN_TASK_NAME}','/F' -Verb RunAs -Wait"
        )
        r2 = subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                            capture_output=True, text=True, timeout=120)
        if r2.returncode == 0:
            return True, "Autorun removed via elevated prompt."
    except Exception:
        pass
    return False, f"schtasks failed ({r.returncode}):\n{r.stderr.strip()}"


def _install_autorun_linux():
    try:
        # Prepare a root helper script that writes files + reloads udev.
        wrapper_doc = WRAPPER_SCRIPT.replace("__APP_PATH__", app_launch_command())
        helper = "/tmp/usb-cleaner-install.sh"
        with open(helper, "w") as f:
            f.write("#!/usr/bin/env bash\nset -e\n")
            f.write(f"cat > {LINUX_WRAPPER_FILE} <<'UCEOF'\n")
            f.write(wrapper_doc)
            f.write("UCEOF\n")
            f.write(f"chmod 0755 {LINUX_WRAPPER_FILE}\n")
            # Make a convenience symlink so udev wrapper is easy to find
            f.write(f"ln -sf {LINUX_WRAPPER_FILE} {LINUX_WRAPPER_LINK} || true\n")
            f.write(f"cat > {LINUX_RULE_FILE} <<'UCEOF'\n")
            f.write("# USB Cleaner autorun rule\n")
            f.write(UDEV_RULE)
            f.write("UCEOF\n")
            f.write("udevadm control --reload-rules || true\n")
        os.chmod(helper, 0o755)
    except OSError as e:
        return False, f"Cannot prepare installer: {e}"

    # Run as root with a graphical auth prompt (pkexec), or sudo.
    for launcher in (["pkexec", helper], ["sudo", "-n", helper]):
        try:
            if shutil.which(launcher[0]) is None:
                continue
            r = subprocess.run(launcher, capture_output=True, text=True, timeout=120)
            if r.returncode == 0:
                return True, "Autorun installed. Insert a USB drive to test it."
        except Exception:
            continue
    return False, (
        "Could not install (needs root). Run this manually:\n"
        f"sudo cat > {LINUX_WRAPPER_FILE} <<'UCEOF'\n{wrapper_doc}UCEOF\n"
        f"sudo chmod 0755 {LINUX_WRAPPER_FILE}\n"
        f"sudo tee {LINUX_RULE_FILE} <<'UCEOF'\n# USB Cleaner autorun rule\n{UDEV_RULE}UCEOF\n"
        "sudo udevadm control --reload-rules"
    )


def _uninstall_autorun_linux():
    helper = "/tmp/usb-cleaner-uninstall.sh"
    try:
        with open(helper, "w") as f:
            f.write("#!/usr/bin/env bash\nset -e\n")
            f.write(f"rm -f {LINUX_WRAPPER_FILE} {LINUX_WRAPPER_LINK} {LINUX_RULE_FILE}\n")
            f.write("udevadm control --reload-rules || true\n")
        os.chmod(helper, 0o755)
    except OSError as e:
        return False, f"Cannot prepare uninstaller: {e}"

    for launcher in (["pkexec", helper], ["sudo", "-n", helper]):
        try:
            if shutil.which(launcher[0]) is None:
                continue
            r = subprocess.run(launcher, capture_output=True, text=True, timeout=120)
            if r.returncode == 0:
                return True, "Autorun removed."
        except Exception:
            continue
    return False, (
        "Could not remove (needs root). Run manually:\n"
        f"sudo rm -f {LINUX_WRAPPER_FILE} {LINUX_WRAPPER_LINK} {LINUX_RULE_FILE}\n"
        "sudo udevadm control --reload-rules"
    )


# ──────────────────────────────────────────────
# Scanner
# ──────────────────────────────────────────────
def resolve_mount_path(path_or_device):
    """Resolve a block device name (e.g. /dev/sdb1) to its mount point.

    If `path_or_device` is already a mounted directory, returns it unchanged.
    If it's a device node, queries lsblk for the mountpoint and returns it.
    Returns None on failure.
    """
    if os.path.isdir(path_or_device):
        return path_or_device

    dev = path_or_device if path_or_device.startswith("/dev/") else f"/dev/{path_or_device}"
    if not dev.startswith("/dev/"):
        dev = "/dev/" + dev
    try:
        output = subprocess.run(
            ["lsblk", "-rno", "MOUNTPOINT", dev],
            capture_output=True, text=True, timeout=10, check=False,
        ).stdout
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("/") and os.path.isdir(line):
                return line
    except Exception:
        pass
    return None
class ScanResult:
    def __init__(self):
        self.shortcuts = []
        self.autorun_files = []
        self.suspicious_scripts = []
        self.hidden_folders = []
        self.suspicious_folders = []
        self.errors = []
        self.total_scanned = 0

    @property
    def total_threats(self):
        return (len(self.shortcuts) + len(self.autorun_files) +
                len(self.suspicious_scripts) + len(self.hidden_folders) +
                len(self.suspicious_folders))

    def summary_text(self, cleaned=False):
        action = "Cleaned" if cleaned else "Found"
        lines = [
            f"{'=' * 45}",
            f"  USB Virus Scan {'Report' if not cleaned else 'Summary'}",
            f"{'=' * 45}",
            f"  Files scanned    : {self.total_scanned}",
            f"  Shortcuts (.lnk) : {action} {len(self.shortcuts)}",
            f"  Autorun files    : {action} {len(self.autorun_files)}",
            f"  Suspicious scripts: {action} {len(self.suspicious_scripts)}",
            f"  Hidden folders   : {action} {len(self.hidden_folders)}",
            f"  Suspicious folders: {action} {len(self.suspicious_folders)}",
            f"  Errors           : {len(self.errors)}",
            f"{'=' * 45}",
        ]
        return "\n".join(lines)


def scan_drive(path, progress_callback=None):
    """Scan a drive for shortcut virus artifacts."""
    result = ScanResult()
    root = Path(path)

    if not root.exists():
        result.errors.append(f"Path does not exist: {path}")
        return result

    # Build filename patterns
    lnk_files = {".lnk"}
    autorun_files = {"autorun.inf", "autorun.ini"}
    script_exts = {".vbs", ".vbe", ".bat", ".cmd", ".wsf", ".ps1"}
    suspicious_folder_names = {"RECYCLER", "RECYCLED", "msocache", ".trash"}

    all_files = list(root.rglob("*"))
    total = len(all_files) if all_files else 1

    for idx, item in enumerate(all_files):
        if progress_callback:
            progress_callback(idx, total, str(item.name)[:40])

        result.total_scanned += 1

        try:
            if item.is_file():
                name_lower = item.name.lower()

                # Check for .lnk shortcuts
                if item.suffix.lower() == ".lnk":
                    result.shortcuts.append(str(item))
                    continue

                # Check for autorun
                if name_lower in {"autorun.inf", "autorun.ini"}:
                    result.autorun_files.append(str(item))
                    continue

                # Check for malicious scripts
                if item.suffix.lower() in script_exts:
                    # Only flag scripts in root or top-level dirs, not nested deep
                    try:
                        rel = item.relative_to(root)
                        if len(rel.parts) <= 2:
                            result.suspicious_scripts.append(str(item))
                    except ValueError:
                        result.suspicious_scripts.append(str(item))
                    continue

                # Check hidden + system attribute files in root
                try:
                    st = item.stat()
                    attrs = st.st_file_attributes if hasattr(st, 'st_file_attributes') else 0
                    is_hidden = bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN) if platform.system() == "Windows" else bool(st.st_mode & (stat.S_IXUSR >> 3))
                except Exception:
                    is_hidden = False

                # Check for hidden files at root level
                if item.parent == root and item.suffix.lower() not in {'.', '..'}:
                    try:
                        if platform.system() == "Windows":
                            import ctypes
                            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(item))
                            if attrs & stat.FILE_ATTRIBUTE_HIDDEN:
                                result.hidden_folders.append(str(item))
                        elif item.name.startswith('.'):
                            result.hidden_folders.append(str(item))
                    except Exception:
                        pass

            elif item.is_dir():
                name = item.name

                # Check for suspicious folder names
                if name in suspicious_folder_names:
                    result.suspicious_folders.append(str(item))
                    continue

                # Check for hidden/system folders at root level
                if item.parent == root:
                    try:
                        if platform.system() == "Windows":
                            import ctypes
                            attrs = ctypes.windll.kernel32.GetFileAttributesW(str(item))
                            if attrs >= 0 and (attrs & stat.FILE_ATTRIBUTE_HIDDEN):
                                result.hidden_folders.append(str(item))
                        elif name.startswith('.'):
                            result.hidden_folders.append(str(item))
                    except Exception:
                        pass

        except (PermissionError, OSError) as e:
            result.errors.append(f"Access error: {item} - {e}")
        except Exception as e:
            result.errors.append(f"Error scanning {item}: {e}")

    if progress_callback:
        progress_callback(total, total, "Scan complete")

    return result


# ──────────────────────────────────────────────
# Backup
# ──────────────────────────────────────────────
def backup_threats(drive_path, scan_result):
    """Backup all detected threats before cleaning."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    drive_name = Path(drive_path).name or "unknown"
    desktop = Path.home() / "Desktop"
    backup_dir = desktop / f"USB_Backup_{drive_name}_{timestamp}"
    backup_dir.mkdir(parents=True, exist_ok=True)

    all_threats = (scan_result.shortcuts + scan_result.autorun_files +
                   scan_result.suspicious_scripts + scan_result.hidden_folders +
                   scan_result.suspicious_folders)

    backed_up = 0
    errors = []
    for threat_path in all_threats:
        src = Path(threat_path)
        if not src.exists():
            continue
        try:
            # Preserve relative path structure
            try:
                rel = src.relative_to(Path(drive_path))
            except ValueError:
                rel = Path(src.name)
            dest = backup_dir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if src.is_file():
                shutil.copy2(str(src), str(dest))
            elif src.is_dir():
                shutil.copytree(str(src), str(dest), dirs_exist_ok=True)
            backed_up += 1
        except Exception as e:
            errors.append(f"Backup failed for {src}: {e}")

    return {
        "backup_dir": str(backup_dir),
        "files_backed_up": backed_up,
        "errors": errors
    }


# ──────────────────────────────────────────────
# Cleaner
# ──────────────────────────────────────────────
def clean_threats(drive_path, scan_result, progress_callback=None):
    """Remove detected threats and unhide original files."""
    cleaned = 0
    unhided = 0
    errors = []
    all_threats = (scan_result.shortcuts + scan_result.autorun_files +
                   scan_result.suspicious_scripts)

    total = len(all_threats) + len(scan_result.hidden_folders)
    for idx, threat_path in enumerate(all_threats):
        if progress_callback:
            progress_callback(idx, total, f"Deleting: {Path(threat_path).name}")
        try:
            p = Path(threat_path)
            if p.exists():
                if p.is_file():
                    p.unlink()
                elif p.is_dir():
                    shutil.rmtree(str(p))
                cleaned += 1
        except Exception as e:
            errors.append(f"Failed to delete {threat_path}: {e}")

    # Unhide folders
    for hidden_path in scan_result.hidden_folders:
        idx += 1
        if progress_callback:
            progress_callback(idx, total, f"Unhiding: {Path(hidden_path).name}")
        try:
            p = Path(hidden_path)
            if not p.exists():
                continue
            if platform.system() == "Windows":
                import ctypes
                FILE_ATTRIBUTE_NORMAL = 0x80
                ctypes.windll.kernel32.SetFileAttributesW(str(p), FILE_ATTRIBUTE_NORMAL)
            else:
                # Remove leading dot for Linux hidden files
                if p.name.startswith('.'):
                    new_name = p.parent / p.name[1:]
                    if not new_name.exists():
                        p.rename(new_name)
            unhided += 1
        except Exception as e:
            errors.append(f"Failed to unhide {hidden_path}: {e}")

    if progress_callback:
        progress_callback(total, total, "Cleaning complete")

    return {"deleted": cleaned, "unhided": unhided, "errors": errors}


# ──────────────────────────────────────────────
# GUI Application
# ──────────────────────────────────────────────
class USBCleanerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("USB Shortcut Virus Remover")
        self.root.geometry("800x660")
        self.root.minsize(720, 560)
        self.root.configure(bg="#f0f0f0")

        self.scan_result = None
        self.current_drive = None
        self.scan_thread = None
        self.clean_thread = None
        self._prompted_paths = set()

        self._build_ui()

        # Auto-detect newly inserted USB drives
        self.watcher = DriveWatcher(self._on_new_drive)
        self.watcher.start()

    def _build_ui(self):
        # Windows-style palette
        WINDOW_BG = "#f0f0f0"      # classic system grey
        CARD_BG = "#ffffff"
        CARD_BORDER = "#d5d5d5"
        BLUE = "#0078d4"           # Windows accent
        BLUE_HOVER = "#106ebe"
        TEXT = "#1a1a1a"
        MUTED = "#6a6a6a"
        ROW_SEL = "#cde4f7"

        style = ttk.Style()
        style.theme_use("clam")

        # Smaller default font -> also shrinks messagebox/dialog text
        for opt, fam, sz in (("*TkDefaultFont", "Segoe UI", 9),
                             ("*TkTextFont", "Segoe UI", 9),
                             ("*Message.font", "Segoe UI", 9),
                             ("*Dialog.msg.font", "Segoe UI", 9),
                             ("*Dialog.butfont", "Segoe UI", 9)):
            try:
                self.root.option_add(opt, (fam, sz))
            except Exception:
                pass

        style.configure("TFrame", background=WINDOW_BG)
        style.configure("Card.TFrame", background=CARD_BG, relief="flat")
        style.configure("TLabel", background=WINDOW_BG, foreground=TEXT,
                        font=("Segoe UI", 10))
        style.configure("Card.TLabel", background=CARD_BG, foreground=TEXT,
                        font=("Segoe UI", 10))
        style.configure("Muted.Card.TLabel", background=CARD_BG, foreground=MUTED,
                        font=("Segoe UI", 9))
        style.configure("Header.TLabel", background=BLUE, foreground="#ffffff",
                        font=("Segoe UI", 13, "bold"), padding=(16, 9))

        # Windows-style buttons
        style.configure("TButton", font=("Segoe UI", 10), padding=(14, 6),
                        background=CARD_BG, foreground=TEXT, bordercolor=CARD_BORDER,
                        relief="flat", focuscolor=CARD_BG)
        style.map("TButton",
                  background=[("pressed", "#e5e5e5"), ("active", "#f5f5f5"),
                              ("disabled", "#f5f5f5")],
                  bordercolor=[("active", "#7eb4ea"), ("disabled", CARD_BORDER)],
                  foreground=[("disabled", "#a0a0a0")])

        style.configure("Primary.TButton", font=("Segoe UI", 10, "bold"),
                        padding=(16, 7), background=BLUE, foreground="#ffffff",
                        bordercolor=BLUE, relief="flat")
        style.map("Primary.TButton",
                  background=[("pressed", "#005a9e"), ("active", BLUE_HOVER),
                              ("disabled", "#9cc7e8")],
                  bordercolor=[("active", BLUE_HOVER), ("disabled", "#9cc7e8")],
                  foreground=[("disabled", "#ffffff")])

        style.configure("Small.TButton", padding=(8, 4), font=("Segoe UI", 9))

        # Combobox (Windows readonly look)
        style.configure("TCombobox", font=("Segoe UI", 10), fieldbackground=CARD_BG,
                        background=CARD_BG, foreground=TEXT,
                        arrowcolor=TEXT, bordercolor=CARD_BORDER,
                        lightcolor=CARD_BG, darkcolor=CARD_BG, padding=4)
        style.map("TCombobox",
                  fieldbackground=[("readonly", CARD_BG)],
                  selectbackground=[("readonly", ROW_SEL)],
                  selectforeground=[("readonly", TEXT)],
                  bordercolor=[("focus", BLUE), ("active", "#7eb4ea")])

        # Treeview (list pane)
        style.configure("Treeview", background=CARD_BG, fieldbackground=CARD_BG,
                        foreground=TEXT, borderwidth=1, relief="solid",
                        rowheight=24, font=("Segoe UI", 9))
        style.map("Treeview", background=[("selected", ROW_SEL)],
                  foreground=[("selected", TEXT)])
        style.configure("Treeview.Heading", background="#f3f3f3", foreground=TEXT,
                        font=("Segoe UI", 9, "bold"), borderwidth=1,
                        relief="solid", padding=(6, 5))
        style.map("Treeview.Heading", background=[("active", "#e8e8e8")])

        style.configure("TProgressbar", background=BLUE, troughcolor="#e6e6e6",
                        borderwidth=0, lightcolor=BLUE, darkcolor=BLUE)
        style.configure("Status.TLabel", background="#f0f0f0", foreground=TEXT,
                        font=("Segoe UI", 9))

        # ── Header ──
        header = ttk.Label(self.root, text="USB Shortcut Virus Remover",
                           style="Header.TLabel", anchor="w")
        header.pack(fill="x")

        # ── Drive selection card ──
        self._drive_card = tk.Frame(self.root, bg=CARD_BG,
                                    highlightbackground=CARD_BORDER,
                                    highlightthickness=1)
        self._drive_card.pack(fill="x", padx=16, pady=(14, 8))

        inner = tk.Frame(self._drive_card, bg=CARD_BG)
        inner.pack(fill="x", padx=14, pady=10)

        ttk.Label(inner, text="Select drive:", style="Card.TLabel").pack(side="left")

        self.drive_var = tk.StringVar()
        self.drive_combo = ttk.Combobox(inner, textvariable=self.drive_var,
                                        state="readonly", width=46)
        self.drive_combo.pack(side="left", padx=(10, 8))

        self.refresh_btn = ttk.Button(inner, text="Refresh", style="Small.TButton",
                                      command=self.refresh_drives)
        self.refresh_btn.pack(side="left", padx=(0, 6))

        self.browse_btn = ttk.Button(inner, text="Browse...", style="Small.TButton",
                                     command=self.browse_path)
        self.browse_btn.pack(side="left")

        # ── Action buttons card ──
        action_card = tk.Frame(self.root, bg=CARD_BG,
                               highlightbackground=CARD_BORDER,
                               highlightthickness=1)
        action_card.pack(fill="x", padx=16, pady=(0, 8))

        inner = tk.Frame(action_card, bg=CARD_BG)
        inner.pack(fill="x", padx=14, pady=10)

        self.scan_btn = ttk.Button(inner, text="Scan", style="Primary.TButton",
                                   command=self.start_scan)
        self.scan_btn.pack(side="left", padx=(0, 8))

        self.clean_btn = ttk.Button(inner, text="Clean & Fix",
                                    command=self.start_clean, state="disabled")
        self.clean_btn.pack(side="left", padx=(0, 8))

        self.report_btn = ttk.Button(inner, text="View Report",
                                     command=self.show_report, state="disabled")
        self.report_btn.pack(side="left")

        # ── Auto-open bar ──
        auto_card = tk.Frame(self.root, bg=CARD_BG,
                             highlightbackground=CARD_BORDER,
                             highlightthickness=1)
        auto_card.pack(fill="x", padx=16, pady=(0, 8))

        inner = tk.Frame(auto_card, bg=CARD_BG)
        inner.pack(fill="x", padx=14, pady=8)

        self.autorun_btn = ttk.Button(inner, text="Enable", width=9,
                                      style="Small.TButton",
                                      command=self.toggle_autorun)
        self.autorun_btn.pack(side="left", padx=(0, 10))

        ttk.Label(inner, text="Auto-open on USB insert",
                  style="Card.TLabel").pack(side="left", padx=(0, 8))
        self.autorun_status_var = tk.StringVar(value="checking...")
        ttk.Label(inner, textvariable=self.autorun_status_var,
                  style="Muted.Card.TLabel").pack(side="left")

        # Refresh autorun state from OS in a background thread
        def _check():
            try:
                enabled, detail = autorun_status()
            except Exception:
                enabled, detail = False, "unknown"
            self.root.after(0, lambda: self._set_autorun_state(enabled, detail))

        threading.Thread(target=_check, daemon=True).start()

        # ── Progress ──
        self.progress = ttk.Progressbar(self.root, mode="determinate", length=760)
        self.progress.pack(fill="x", padx=16, pady=(0, 4))

        self.progress_label = ttk.Label(self.root, text="Ready",
                                        style="Muted.Card.TLabel")
        self.progress_label.pack(fill="x", padx=16, pady=(0, 6))

        # ── Results treeview ──
        tree_frame = tk.Frame(self.root, bg=CARD_BG,
                              highlightbackground=CARD_BORDER,
                              highlightthickness=1)
        tree_frame.pack(fill="both", expand=True, padx=16, pady=(0, 8))

        columns = ("type", "path")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings",
                                 selectmode="browse")
        self.tree.heading("type", text="Threat Type")
        self.tree.heading("path", text="File Path")
        self.tree.column("type", width=170, minwidth=120)
        self.tree.column("path", width=560, minwidth=300)

        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True, padx=(1, 0), pady=1)
        scrollbar.pack(side="right", fill="y")

        # ── Status bar ──
        self.status_var = tk.StringVar(value="Insert a USB drive and click Refresh")
        status_bar = ttk.Label(self.root, textvariable=self.status_var,
                               style="Status.TLabel", anchor="w")
        status_bar.pack(fill="x", side="bottom", padx=4, pady=(0, 4))

        # Init drives
        self.refresh_drives()

    def _set_autorun_state(self, enabled, detail):
        self._autorun_enabled = enabled
        self.autorun_status_var.set(detail)
        self.autorun_btn.configure(text="Disable" if enabled else "Enable")

    def toggle_autorun(self):
        current = getattr(self, "_autorun_enabled", False)
        action = "Disable" if current else "Enable"
        if not messagebox.askokcancel(action, f"{action} auto-open on USB insert?"):
            return
        self.autorun_btn.configure(state="disabled")

        def _run():
            try:
                ok, msg = (uninstall_autorun if current else install_autorun)()
                self.root.after(0, lambda: self._autorun_done(ok, msg))
            except Exception as e:
                self.root.after(0, lambda: self._autorun_done(False, str(e)))

        threading.Thread(target=_run, daemon=True).start()

    def _autorun_done(self, ok, msg):
        self.autorun_btn.configure(state="normal")
        try:
            enabled, detail = autorun_status()
            self._set_autorun_state(enabled, detail)
        except Exception:
            enabled, detail = False, "unknown"
        if not ok:
            messagebox.showerror("Autorun", msg)
        else:
            messagebox.showinfo("Autorun", msg)

    def refresh_drives(self):
        drives = get_removable_drives()
        if not drives:
            self.drive_combo["values"] = ["No removable drives found"]
            self.drive_combo.current(0)
            self.status_var.set("No removable drives detected. Try Browse...")
        else:
            labels = [d["label"] for d in drives]
            self.drive_combo["values"] = labels
            self.drive_combo.current(0)
            self._drives = drives
            self.status_var.set(f"Found {len(drives)} removable drive(s)")

    def _on_new_drive(self, path, label, removed=False):
        """Called from the watcher thread when drives are inserted/removed."""

        def _handle():
            self.refresh_drives()
            if removed:
                return
            if self.scan_thread and self.scan_thread.is_alive():
                return
            if path in self._prompted_paths:
                return
            self._prompted_paths.add(path)
            answer = messagebox.askyesno(
                "New USB Drive Detected",
                f"USB drive detected:\n\n   {label} ({path})\n\n"
                "Would you like to scan it now?"
            )
            if answer:
                try:
                    self.drive_combo.set(path)
                    if hasattr(self, "_drives"):
                        for d in self._drives:
                            if d["path"] == path:
                                idx = self._drives.index(d)
                                self.drive_combo.current(idx)
                                break
                except Exception:
                    pass
                self.start_scan()

        self.root.after(0, _handle)

    def offer_first_removable(self):
        """Used on Windows autostart: offer to scan whichever removable
        drive is connected (the task trigger can't pass a drive letter)."""
        try:
            drives = get_removable_drives()
        except Exception:
            drives = []
        if not drives:
            self.status_var.set("Auto-launched: no removable drive detected yet.")
            return
        self.select_drive_and_prompt(drives[0]["path"])

    def select_drive_and_prompt_with_retry(self, device_or_path, attempts=12):
        """Resolve a device/path to a mounted dir and prompt to scan it.

        Retries for a few seconds because the filesystem may still be
        mounting when the OS triggers this launch.
        """
        path = resolve_mount_path(device_or_path)
        if path:
            self.select_drive_and_prompt(path)
            return

        if attempts <= 0:
            return
        self.root.after(500, lambda: self.select_drive_and_prompt_with_retry(
            device_or_path, attempts - 1))

    def select_drive_and_prompt(self, path):
        """Select a drive path in the dropdown and ask the user to scan it.

        Used when the app is launched by an OS autorun trigger (udev /
        Task Scheduler) right after a USB drive is inserted.
        """
        if not os.path.isdir(path):
            return
        if path in self._prompted_paths:
            return
        self._prompted_paths.add(path)
        # Select the drive in the dropdown if it's a known/listed drive
        try:
            if hasattr(self, "_drives"):
                for d in self._drives:
                    if d["path"] == path:
                        idx = self._drives.index(d)
                        self.drive_combo.current(idx)
                        break
            self.drive_combo.set(path)
        except Exception:
            pass
        self.current_drive = path

        label = Path(path.rstrip("/\\")).name
        answer = messagebox.askyesno(
            "USB Drive Detected",
            f"USB drive detected:\n\n   {label} ({path})\n\n"
            "Would you like to scan it now?"
        )
        if answer and not (self.scan_thread and self.scan_thread.is_alive()):
            self.start_scan()

    def browse_path(self):
        path = filedialog.askdirectory(title="Select USB Drive Path")
        if path:
            self.drive_combo["values"] = [path]
            self.drive_combo.current(0)
            self._drives = [{"path": path, "label": path}]
            self.current_drive = path

    def _get_selected_path(self):
        if hasattr(self, "_drives") and self._drives:
            idx = self.drive_combo.current()
            if 0 <= idx < len(self._drives):
                return self._drives[idx]["path"]
        return self.drive_combo.get()

    def start_scan(self):
        path = self._get_selected_path()
        if not path or not os.path.isdir(path):
            messagebox.showerror("Error", "Please select a valid drive path.")
            return

        self.current_drive = path
        self.scan_btn.configure(state="disabled")
        self.clean_btn.configure(state="disabled")
        self.report_btn.configure(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.progress["value"] = 0

        def _scan():
            def on_progress(current, total, msg):
                self.root.after(0, lambda: self._update_progress(current, total, msg))

            result = scan_drive(path, progress_callback=on_progress)
            self.root.after(0, lambda: self._on_scan_complete(result))

        self.scan_thread = threading.Thread(target=_scan, daemon=True)
        self.scan_thread.start()

    def _update_progress(self, current, total, msg):
        if total > 0:
            pct = min((current / total) * 100, 100)
            self.progress["value"] = pct
        self.progress_label.configure(text=msg[:60])

    def _on_scan_complete(self, result):
        self.scan_result = result
        self.tree.delete(*self.tree.get_children())

        for path in result.shortcuts:
            self.tree.insert("", "end", values=("Shortcut (.lnk)", path))
        for path in result.autorun_files:
            self.tree.insert("", "end", values=("Autorun File", path))
        for path in result.suspicious_scripts:
            self.tree.insert("", "end", values=("Suspicious Script", path))
        for path in result.hidden_folders:
            self.tree.insert("", "end", values=("Hidden Item", path))
        for path in result.suspicious_folders:
            self.tree.insert("", "end", values=("Suspicious Folder", path))

        self.progress["value"] = 100
        threats = result.total_threats
        self.status_var.set(
            f"Scan complete: {threats} threat(s) found in {result.total_scanned} items"
            + (f" ({len(result.errors)} errors)" if result.errors else "")
        )

        self.scan_btn.configure(state="normal")
        if threats > 0:
            self.clean_btn.configure(state="normal")
        self.report_btn.configure(state="normal")

        if threats == 0:
            messagebox.showinfo("Scan Complete",
                                "No shortcut virus artifacts found! Drive appears clean.")

    def start_clean(self):
        if not self.scan_result or self.scan_result.total_threats == 0:
            return

        answer = messagebox.askyesnocancel(
            "Confirm Clean",
            f"Found {self.scan_result.total_threats} threats.\n\n"
            "YES = Backup first, then clean\n"
            "NO = Clean immediately (no backup)\n"
            "CANCEL = Abort"
        )
        if answer is None:
            return

        do_backup = answer
        self.scan_btn.configure(state="disabled")
        self.clean_btn.configure(state="disabled")
        self.progress["value"] = 0

        def _clean():
            backup_info = None
            if do_backup:
                self.root.after(0, lambda: self.progress_label.configure(text="Backing up threats..."))
                try:
                    backup_info = backup_threats(self.current_drive, self.scan_result)
                except Exception as e:
                    self.root.after(0, lambda: messagebox.showerror("Backup Error", str(e)))
                    self.root.after(0, lambda: self.scan_btn.configure(state="normal"))
                    return

            def on_progress(current, total, msg):
                self.root.after(0, lambda: self._update_progress(current, total, msg))

            clean_result = clean_threats(self.current_drive, self.scan_result,
                                          progress_callback=on_progress)
            self.root.after(0, lambda: self._on_clean_complete(clean_result, backup_info))

        self.clean_thread = threading.Thread(target=_clean, daemon=True)
        self.clean_thread.start()

    def _on_clean_complete(self, clean_result, backup_info):
        self.progress["value"] = 100
        self.scan_btn.configure(state="normal")
        self.report_btn.configure(state="normal")

        # Build summary
        lines = [
            "Cleaning Complete!\n",
            f"Files deleted    : {clean_result['deleted']}",
            f"Items unhidden   : {clean_result['unhided']}",
        ]
        if backup_info:
            lines.append(f"Files backed up  : {backup_info['files_backed_up']}")
            lines.append(f"Backup location  : {backup_info['backup_dir']}")
        if clean_result["errors"]:
            lines.append(f"\nErrors ({len(clean_result['errors'])}):")
            for err in clean_result["errors"][:5]:
                lines.append(f"  - {err}")

        self.status_var.set(f"Cleaned: {clean_result['deleted']} deleted, "
                            f"{clean_result['unhided']} unhidden")

        messagebox.showinfo("Clean Complete", "\n".join(lines))

    def show_report(self):
        if not self.scan_result:
            messagebox.showinfo("No Report", "Run a scan first to view the report.")
            return

        report_win = tk.Toplevel(self.root, bg="#f0f0f0")
        report_win.title("Scan Report")
        report_win.geometry("560x520")

        text = tk.Text(report_win, bg="#ffffff", fg="#1a1a1a", relief="solid",
                       borderwidth=1, font=("Consolas", 10), wrap="word",
                       padx=15, pady=15)
        text.pack(fill="both", expand=True, padx=10, pady=10)

        report = self.scan_result.summary_text()
        text.insert("1.0", report)
        text.configure(state="disabled")

        ttk.Button(report_win, text="Close", command=report_win.destroy).pack(pady=10)


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────
def main():
    args = sys.argv[1:]

    # CLI usage:
    #   app /path/to/drive   -> resolve + immediately prompt scan
    #   app /dev/sdb1        -> resolve mount path then prompt
    #   app --autostart      -> (Windows task) open & offer any connected drive
    autostart_path = None
    flag_autostart = False
    for a in args:
        if a in ("--autostart", "-a"):
            flag_autostart = True
            continue
        autostart_path = a
        break

    root = tk.Tk()
    app = USBCleanerApp(root)

    # Set window icon (creeper USB stick) if present next to the script/exe
    _set_window_icon(root)

    def _on_close():
        if hasattr(app, "watcher"):
            app.watcher.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", _on_close)

    if autostart_path:
        root.after(300, lambda: app.select_drive_and_prompt_with_retry(autostart_path))
    elif flag_autostart:
        root.after(400, lambda: app.offer_first_removable())

    root.mainloop()


def _set_window_icon(root):
    """Apply the bundled app icon to the window/taskbar if available."""
    import os as _os

    # PyInstaller onefile extracts data to sys._MEIPASS
    base = getattr(sys, "_MEIPASS", None) or _os.path.dirname(_os.path.abspath(__file__))
    try:
        if platform.system() == "Windows":
            ico = _os.path.join(base, "icon.ico")
            if _os.path.exists(ico):
                root.iconbitmap(ico)
        else:
            png = _os.path.join(base, "icon.png")
            if _os.path.exists(png):
                from tkinter import PhotoImage
                root.iconphoto(True, PhotoImage(file=png))
    except Exception:
        pass


if __name__ == "__main__":
    main()
