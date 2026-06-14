@echo off
setlocal enabledelayedexpansion

echo.
echo ================================================
echo   MalScript Analyzer -- Install Dependencies
echo ================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed.
    echo         Install from https://www.python.org/downloads/
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo [OK] %%v

:: Check Node.js
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js is not installed.
    echo         Install from https://nodejs.org/
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('node --version 2^>^&1') do echo [OK] Node %%v

:: Check Ollama (optional)
ollama --version >nul 2>&1
if errorlevel 1 (
    echo [WARN] Ollama not found -- rule-based fallback will be used.
    echo        Install from: https://ollama.com/download
) else (
    for /f "tokens=*" %%v in ('ollama --version 2^>^&1') do echo [OK] Ollama %%v
)

:: Check Docker (optional - needed for Lab feature)
docker --version >nul 2>&1
if errorlevel 1 (
    echo [WARN] Docker not found -- Docker Lab feature will be unavailable.
    echo        Install Docker Desktop from: https://www.docker.com/products/docker-desktop
) else (
    for /f "tokens=*" %%v in ('docker --version 2^>^&1') do echo [OK] %%v
    :: Check Docker daemon
    docker info >nul 2>&1
    if errorlevel 1 (
        echo [WARN] Docker is installed but daemon is not running.
        echo        Start Docker Desktop before using the Lab feature.
    ) else (
        echo [OK] Docker daemon is running
    )
)

echo.
echo -- 1/2  Installing Python packages ----------------
cd /d "%~dp0backend"
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] pip install failed
    pause & exit /b 1
)
echo [OK] Python packages installed

echo.
echo -- 2/2  Installing Node packages ------------------
cd /d "%~dp0frontend"
npm install
if errorlevel 1 (
    echo [ERROR] npm install failed
    pause & exit /b 1
)
echo [OK] Node packages installed

:: Create .env if missing
if not exist "%~dp0backend\.env" (
    copy "%~dp0backend\.env.example" "%~dp0backend\.env" >nul
    echo.
    echo [INFO] backend\.env created from .env.example
    echo        Set ANTHROPIC_API_KEY to enable Claude deep analysis.
    echo        Without it the service runs in fallback mode.
)

echo.
echo ================================================
echo   Done!  Run start.bat to launch the service.
echo ================================================
echo.
pause
