@echo off
REM Artemis v15 -- install Python dependencies
REM Run this once before first launch.

cd /d "%~dp0"

echo Installing Artemis dependencies...
echo.
echo   psutil    - TCP endpoint enumeration
echo   pydivert  - UDP packet capture (requires admin at runtime)
echo   pillow    - GIF + emoji rendering in the GUI
echo.

pip install psutil pydivert pillow

echo.
echo Dependencies installed. You can now run:
echo   run_artemis_admin.bat   (full UDP capture, requires admin elevation)
echo   run_artemis.bat         (TCP-only, no admin needed but limited)
echo.
pause
