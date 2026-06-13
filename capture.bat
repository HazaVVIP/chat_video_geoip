@echo off
REM Capture live + analisis geolokasi (butuh CMD Run as Administrator)
REM Usage: capture.bat "Wi-Fi" 120 meeting.pcap
setlocal
cd /d "%~dp0"

set IFACE=%~1
set SEC=%~2
set OUT=%~3

if "%IFACE%"=="" (
    echo Usage: capture.bat INTERFACE SECONDS [output.pcap]
    echo Example: capture.bat "Wi-Fi" 120 meeting.pcap
    echo.
    call run.bat --list-interfaces
    exit /b 1
)

if "%SEC%"=="" set SEC=60
if "%OUT%"=="" set OUT=capture_%date:~-4,4%%date:~-7,2%%date:~-10,2%_%time:~0,2%%time:~3,2%%time:~6,2%.pcap
set OUT=%OUT: =0%

echo [*] Capture %SEC%s on %IFACE% -^> %OUT%
call run.bat -i "%IFACE%" -c %SEC% -w "%OUT%" -o json --out-file "%OUT%.geo.json"
exit /b %errorlevel%
