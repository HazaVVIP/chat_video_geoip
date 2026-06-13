@echo off
REM Self-check smoke test
setlocal
cd /d "%~dp0"
call run.bat --check
exit /b %errorlevel%
