@echo off
REM ============================================================
REM  USB Shortcut Virus Remover - Windows build script
REM  Builds a single portable USB Virus Cleaner.exe with PyInstaller
REM ============================================================
setlocal
cd /d "%~dp0"

echo === USB Shortcut Virus Remover - Windows Build ===

REM 0. Check Python
where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.9+ and retry.
    pause
    exit /b 1
)

REM 1. Install build deps
echo [1/3] Installing build dependencies...
python -m pip install --upgrade pip
python -m pip install -r requirements.txt pyinstaller
if errorlevel 1 (
    echo [INFO] Initial pip install failed, retrying with --break-system-packages...
    python -m pip install --break-system-packages -r requirements.txt pyinstaller
)
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

REM 2. Build icon
echo [2/3] Generating application icon...
python build_icon.py
if errorlevel 1 (
    echo [WARN] Icon generation failed, building with default icon.
)

REM 3. PyInstaller - one-file portable executable
echo [3/3] Building portable executable with PyInstaller...
python -m PyInstaller ^
    --noconfirm ^
    --onefile ^
    --windowed ^
    --name "USB Virus Cleaner" ^
    --icon icon.ico ^
    --add-data "icon.ico;." ^
    --clean ^
    --exclude-module PIL ^
    --exclude-module numpy ^
    usb_cleaner.py
if errorlevel 1 (
    echo [ERROR] PyInstaller build failed.
    pause
    exit /b 1
)

echo.
echo === BUILD COMPLETE ===
echo Portable executable: dist\USB Virus Cleaner.exe
echo Copy that ONE file to any USB drive / PC - no install needed.
pause
endlocal