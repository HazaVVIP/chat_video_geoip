@echo off
REM Mode live — tampil terus sampai Ctrl+C (CMD Run as Administrator)
REM Usage: live.bat [INTERFACE]  atau  live.bat  (auto-select)
setlocal
cd /d "%~dp0"

set IFACE=%~1
if "%IFACE%"=="" (
    echo [*] Tanpa argumen — list interface + auto-select
    call run.bat --list-interfaces
    echo.
    echo [*] LIVE mode default: --filter-preset all
    call run.bat --live --auto-interface --filter-preset all %2 %3 %4 %5 %6 %7 %8 %9
    exit /b %errorlevel%
)

echo [*] LIVE mode — tekan Ctrl+C untuk berhenti
call run.bat --live -i "%IFACE%" --filter-preset all %2 %3 %4 %5 %6 %7 %8 %9
exit /b %errorlevel%
