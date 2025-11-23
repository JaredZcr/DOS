@echo off
title DoS Monitor Launcher
color 0A

echo ==========================================
echo      SecOps Network Guard Launcher
echo ==========================================

cd /d "%~dp0"

if not exist "index.html" (
    echo [ERROR] index.html not found!
    pause
    exit
)

if not exist "DOS.exe" (
    echo [ERROR] DOS.exe not found! Please compile your C code first.
    pause
    exit
)

echo [1/3] Starting Python Web Server...
start "" /min python -m http.server 8000

echo [2/3] Opening Dashboard in Browser...
timeout /t 1 >nul
start http://localhost:8000

echo [3/3] Starting C Backend...
start "" "DOS.exe"

echo.
echo All systems go! You can minimize this window.
echo.