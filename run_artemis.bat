@echo off
REM Artemis v15 -- TCP-only mode (no admin required)
REM Without admin, WinDivert can't capture UDP packets, so you won't see
REM live packet stats or get match confirmation. Use run_artemis_admin.bat
REM for the real experience.

cd /d "%~dp0"
python artemis.py
pause
