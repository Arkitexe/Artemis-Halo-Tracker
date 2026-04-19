@echo off
REM Artemis v15 -- build the standalone .exe
REM
REM Requires: Python 3.9+ with pip on PATH
REM Output:   dist\Artemis.exe (single-file, ~40-60 MB)

cd /d "%~dp0"

echo ============================================================
echo  Artemis v15 -- building Artemis.exe
echo ============================================================
echo.

REM 1) Make sure all build deps are installed
echo [1/4] Installing / verifying build dependencies...
pip install --quiet pyinstaller psutil pydivert Pillow
if errorlevel 1 (
    echo.
    echo ERROR: pip install failed. Is Python on your PATH?
    pause
    exit /b 1
)

REM 2) Clean old build artifacts so we don't ship stale stuff
echo [2/4] Cleaning old build artifacts...
if exist build  rmdir /s /q build
if exist dist   rmdir /s /q dist

REM 3) Run PyInstaller with the shipped spec
echo [3/4] Running PyInstaller (this takes 1-3 minutes)...
pyinstaller --noconfirm artemis.spec
if errorlevel 1 (
    echo.
    echo ERROR: PyInstaller failed. See output above.
    pause
    exit /b 1
)

REM 4) Sanity-check the output
echo [4/4] Verifying output...
if not exist "dist\Artemis.exe" (
    echo.
    echo ERROR: dist\Artemis.exe was not produced.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  BUILD COMPLETE
echo ============================================================
echo.
echo  Output:  %~dp0dist\Artemis.exe
echo.
echo  To run with UDP packet capture (recommended):
echo    right-click dist\Artemis.exe -> Run as administrator
echo.
echo  WinDivert driver will install silently on first launch.
echo ============================================================
echo.
pause
