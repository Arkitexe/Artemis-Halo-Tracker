@echo off
REM =========================================================
REM Artemis v15 -- build the installer (Artemis_Setup_v15.exe)
REM
REM Prerequisites:
REM   1. Inno Setup installed (free): https://jrsoftware.org/isdl.php
REM   2. build_exe.bat already run (i.e. dist\Artemis.exe exists)
REM =========================================================

cd /d "%~dp0"

echo ============================================================
echo  Artemis v15 -- installer builder
echo ============================================================
echo.

REM Step 0: verify the PyInstaller output exists
if not exist "dist\Artemis.exe" (
    echo ERROR: dist\Artemis.exe not found.
    echo.
    echo Please run build_exe.bat FIRST to produce the application exe,
    echo THEN run this script to wrap it in an installer.
    echo.
    pause
    exit /b 1
)

REM Step 1: locate Inno Setup Compiler (iscc.exe)
set "ISCC="
if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"      set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe"           set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if exist "%ProgramFiles(x86)%\Inno Setup 5\ISCC.exe"      set "ISCC=%ProgramFiles(x86)%\Inno Setup 5\ISCC.exe"
if exist "%ProgramFiles%\Inno Setup 5\ISCC.exe"           set "ISCC=%ProgramFiles%\Inno Setup 5\ISCC.exe"

if "%ISCC%"=="" (
    echo ERROR: Inno Setup Compiler ^(iscc.exe^) not found.
    echo.
    echo Download and install Inno Setup ^(free^) from:
    echo   https://jrsoftware.org/isdl.php
    echo.
    echo Then run this script again.
    echo.
    pause
    exit /b 1
)

echo Using Inno Setup at:  %ISCC%
echo.

REM Step 2: compile artemis.iss -> installer\Artemis_Setup_v15.0.0.exe
echo Compiling installer...
"%ISCC%" /Q artemis.iss
if errorlevel 1 (
    echo.
    echo ERROR: Inno Setup failed. See output above.
    pause
    exit /b 1
)

REM Step 3: sanity-check output
if not exist "installer\Artemis_Setup_Beta.exe" (
    echo.
    echo ERROR: installer\Artemis_Setup_Beta.exe was not produced.
    pause
    exit /b 1
)

echo.
echo ============================================================
echo  INSTALLER READY
echo ============================================================
echo.
echo  File:  %~dp0installer\Artemis_Setup_Beta.exe
echo.
echo  Send this single file to your friend. Running it will:
echo    - Show a welcome screen with the Artemis branding
echo    - Ask them to accept the license
echo    - Install to Program Files\Artemis
echo    - Create Start Menu + optional Desktop shortcut
echo    - Register an uninstaller under Add/Remove Programs
echo.
echo  They do NOT need Python or any other dependencies.
echo ============================================================
echo.
pause
