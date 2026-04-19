@echo off
REM Artemis v15 -- admin launcher (required for UDP packet capture via WinDivert)
REM This will prompt UAC. Without admin, the live stats panel and match
REM detection don't work because pydivert needs kernel-level access.

cd /d "%~dp0"

REM Try to elevate if we're not admin
net session >nul 2>&1
if %errorlevel% neq 0 (
  echo Requesting admin privileges for WinDivert UDP capture...
  powershell -Command "Start-Process cmd -ArgumentList '/c cd /d \"%~dp0\" && python artemis.py' -Verb RunAs"
  exit /b
)

python artemis.py
pause
