@echo off
cd /d "%~dp0"
where python >nul 2>nul
if %errorlevel% equ 0 (
  python backend.py
  goto :end
)
where py >nul 2>nul
if %errorlevel% equ 0 (
  py backend.py
  goto :end
)
echo.
echo Python 3.10 or newer is required.
echo Install it from https://www.python.org/downloads/windows/ and run this file again.
pause
:end
