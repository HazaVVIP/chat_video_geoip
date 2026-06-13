@echo off
REM Mode live — tampil terus sampai Ctrl+C (CMD Run as Administrator)
REM Usage: live.bat "Wi-Fi"
setlocal
cd /d "%~dp0"

set IFACE=%~1
if "%IFACE%"=="" (
    echo Usage: live.bat "INTERFACE"
    echo.
    call run.bat --list-interfaces
    exit /b 1
)

echo [*] LIVE mode — tekan Ctrl+C untuk berhenti
call run.bat --live -i "%IFACE%" %2 %3 %4 %5 %6 %7 %8 %9
exit /b %errorlevel%
