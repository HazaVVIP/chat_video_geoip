@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

echo [*] Chat/Video GeoIP — setup Windows
echo.

set PY=
set PY_OK=0

REM 1) Python Launcher (py.exe) — paling andal di Windows
where py >nul 2>&1
if !errorlevel!==0 (
    py -3 --version >nul 2>&1
    if !errorlevel!==0 (
        set PY=py -3
        set PY_OK=1
    )
)

REM 2) python.exe di PATH (hindari stub WindowsApps / Microsoft Store)
if !PY_OK!==0 (
    for /f "delims=" %%P in ('where python 2^>nul') do (
        echo %%P | findstr /i "WindowsApps" >nul
        if !errorlevel! neq 0 (
            "%%P" --version >nul 2>&1
            if !errorlevel!==0 (
                set "PY=%%P"
                set PY_OK=1
                goto found_py
            )
        )
    )
)

REM 3) Lokasi instalasi umum
if !PY_OK!==0 (
    for %%P in (
        "%LocalAppData%\Programs\Python\Python312\python.exe"
        "%LocalAppData%\Programs\Python\Python311\python.exe"
        "%LocalAppData%\Programs\Python\Python310\python.exe"
        "C:\Python312\python.exe"
        "C:\Python311\python.exe"
    ) do (
        if exist %%P (
            %%P --version >nul 2>&1
            if !errorlevel!==0 (
                set "PY=%%P"
                set PY_OK=1
                goto found_py
            )
        )
    )
)

:found_py
if !PY_OK!==0 goto no_python

echo [*] Python OK:
!PY! --version
echo.

echo [*] Upgrade pip + install dependensi...
!PY! -m pip install --upgrade pip
if !errorlevel! neq 0 goto pip_fail

!PY! -m pip install -r "%~dp0requirements.txt"
if !errorlevel! neq 0 goto pip_fail

echo.
echo [*] Install Playwright Chromium (hybrid mode)...
!PY! -m playwright install chromium
if !errorlevel! neq 0 (
    echo [!] Playwright install gagal — hybrid mode tidak tersedia
)

echo.
echo [OK] Dependensi terpasang.
echo.
call :check_tshark
echo.
echo [*] Self-check...
call "%~dp0run.bat" --check
echo.
echo Selanjutnya:
echo   run.bat --version
echo   run.bat --ip 8.8.8.8
echo   run.bat omegle
echo   run.bat --hybrid --auto-interface --platform ometv
echo.
pause
exit /b 0

:no_python
echo [X] Python ASLI tidak ditemukan.
echo.
echo where python menunjuk ke stub Store (WindowsApps) — bukan Python beneran.
echo.
echo FIX:
echo   1. Buka: https://www.python.org/downloads/windows/
echo   2. Download "Windows installer (64-bit)"
echo   3. Jalankan installer, CENTANG:
echo        [x] Add python.exe to PATH
echo        [x] Install pip
echo   4. Tutup CMD ini, buka CMD BARU
echo   5. Jalankan setup.bat lagi
echo.
echo Opsional — matikan alias Store:
echo   Settings ^> Apps ^> Advanced app settings ^> App execution aliases
echo   Matikan "python.exe" dan "python3.exe"
echo.
pause
exit /b 1

:pip_fail
echo.
echo [X] pip gagal. Coba manual:
echo   python -m pip install -r requirements.txt
echo.
pause
exit /b 1

:check_tshark
where tshark >nul 2>&1
if !errorlevel!==0 (
    echo [OK] tshark: 
    tshark -v 2>nul | findstr /i "TShark"
    exit /b 0
)
if exist "C:\Program Files\Wireshark\tshark.exe" (
    echo [OK] tshark ada di Program Files ^(tambahkan ke PATH atau pakai full path^)
    exit /b 0
)
echo [!] tshark belum ada — install Wireshark:
echo     https://www.wireshark.org/download.html
echo     Centang "TShark" saat install.
exit /b 0
