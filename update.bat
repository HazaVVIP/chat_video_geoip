@echo off
REM Verify deploy bundle — semua file wajib ada + VERSION match
setlocal EnableDelayedExpansion
cd /d "%~dp0"

set FAIL=0
set VER=
if exist VERSION (
    set /p VER=<VERSION
    echo [*] Bundle version: !VER!
) else (
    echo [X] VERSION missing
    set FAIL=1
)

for %%F in (
    chat_video_geoip.py
    run.bat
    live.bat
    check.bat
    capture.bat
    setup.bat
    update.bat
    requirements.txt
    README.md
    VERSION
    inject\webrtc_hook.js
    chat_geoip\cli.py
    chat_geoip\config.py
    chat_geoip\hybrid.py
) do (
    if exist "%%F" (
        echo [OK] %%F
    ) else (
        echo [X] MISSING: %%F
        set FAIL=1
    )
)

echo.
call run.bat --version
if !errorlevel! neq 0 set FAIL=1

echo.
if !FAIL!==0 (
    echo [OK] Deploy bundle lengkap
    exit /b 0
) else (
    echo [X] Deploy bundle TIDAK lengkap — copy ulang folder
    exit /b 1
)
