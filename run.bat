@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

set PY=
where py >nul 2>&1 && py -3 --version >nul 2>&1 && set "PY=py -3" && goto init
for /f "delims=" %%P in ('where python 2^>nul') do (
    echo %%P | findstr /i "WindowsApps" >nul
    if !errorlevel! neq 0 (
        "%%P" --version >nul 2>&1 && set "PY=%%P" && goto init
    )
)
for %%P in ("%LocalAppData%\Programs\Python\Python312\python.exe") do (
    if exist %%P set "PY=%%P" & goto init
)
echo Python tidak ditemukan.
exit /b 1

:init
if exist "C:\Program Files\Wireshark\tshark.exe" set "PATH=C:\Program Files\Wireshark;%PATH%"
if exist "%~dp0GeoLite2-City.mmdb" set "GEOLITE2_CITY_DB=%~dp0GeoLite2-City.mmdb"

if /i "%~1"=="omegle" goto omegle_hybrid
if /i "%~1"=="ometv" goto omegle_hybrid
goto run

:omegle_hybrid
REM Hybrid APT — OmeTV/Omegle (butuh CMD Run as Administrator)
shift

net session >nul 2>&1
if !errorlevel! neq 0 (
    echo [X] Butuh CMD Run as Administrator untuk capture Npcap
    echo     Klik kanan CMD ^> Run as administrator
    pause
    exit /b 1
)

set IFACE=%~1
set HYBRID_ARGS=--hybrid --platform ometv --filter-preset omegle-ometv

if "!IFACE!"=="" (
    echo [*] HYBRID APT mode — OmeTV ^(auto-interface^)
    echo [*] Browser + tshark paralel. Ctrl+C untuk stop.
    echo.
    !PY! "%~dp0chat_video_geoip.py" !HYBRID_ARGS! --auto-interface %1 %2 %3 %4 %5 %6 %7 %8
    exit /b !errorlevel!
)

echo [*] HYBRID APT mode — OmeTV
echo [*] Interface: !IFACE!
echo [*] Browser + tshark paralel. Ctrl+C untuk stop.
shift
!PY! "%~dp0chat_video_geoip.py" !HYBRID_ARGS! -i "!IFACE!" %1 %2 %3 %4 %5 %6 %7 %8
exit /b !errorlevel!

:run
!PY! "%~dp0chat_video_geoip.py" %*
