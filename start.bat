@echo off
setlocal

if not exist "%~dp0backend\requirements.txt" (
    echo [ERROR] Project structure invalid. Run install.bat first.
    pause & exit /b 1
)

python "%~dp0start_all.py"

if errorlevel 1 pause
