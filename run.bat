@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

set PY=
where py >nul 2>&1 && py -3 --version >nul 2>&1 && set "PY=py -3" && goto run
for /f "delims=" %%P in ('where python 2^>nul') do (
    echo %%P | findstr /i "WindowsApps" >nul
    if !errorlevel! neq 0 (
        "%%P" --version >nul 2>&1 && set "PY=%%P" && goto run
    )
)
for %%P in ("%LocalAppData%\Programs\Python\Python312\python.exe") do (
    if exist %%P set "PY=%%P" & goto run
)
echo Python tidak ditemukan.
exit /b 1

:run
if exist "C:\Program Files\Wireshark\tshark.exe" set "PATH=C:\Program Files\Wireshark;%PATH%"
if exist "%~dp0GeoLite2-City.mmdb" set "GEOLITE2_CITY_DB=%~dp0GeoLite2-City.mmdb"
!PY! "%~dp0chat_video_geoip.py" %*
