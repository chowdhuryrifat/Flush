@echo off
REM ============================================================
REM  Portable launcher for USB Shortcut Virus Remover (Windows)
REM  Drop this ENTIRE folder on a USB stick; double-click this.
REM  Prefers the built .exe, falls back to running from source.
REM ============================================================
setlocal
cd /d "%~dp0"

if exist "dist\USB Virus Cleaner.exe" (
    start "" "dist\USB Virus Cleaner.exe"
    exit /b 0
)

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] No built EXE found and Python is not installed.
    echo         Build the EXE first on a dev PC with: build_windows.bat
    pause
    exit /b 1
)

python usb_cleaner.py
exit /b %errorlevel%
endlocal