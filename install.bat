@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo.
echo ╔══════════════════════════════════════════════╗
echo ║       MalScript Analyzer — 의존성 설치       ║
echo ╚══════════════════════════════════════════════╝
echo.

:: ── Python 확인 ──
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python 이 설치되어 있지 않습니다.
    echo         https://www.python.org/downloads/ 에서 설치 후 재실행하세요.
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo [OK] %%v

:: ── Node.js 확인 ──
node --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js 가 설치되어 있지 않습니다.
    echo         https://nodejs.org/ 에서 설치 후 재실행하세요.
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('node --version 2^>^&1') do echo [OK] Node %%v

:: ── Ollama 확인 (선택) ──
ollama --version >nul 2>&1
if errorlevel 1 (
    echo [WARN] Ollama 미설치 — 규칙 기반 폴백으로만 동작합니다.
    echo        설치: https://ollama.com/download
) else (
    for /f "tokens=*" %%v in ('ollama --version 2^>^&1') do echo [OK] Ollama %%v
)

echo.
echo ── 1/2  Python 패키지 설치 중 ─────────────────
cd /d "%~dp0backend"
pip install -r requirements.txt
if errorlevel 1 (
    echo [ERROR] pip install 실패
    pause & exit /b 1
)
echo [OK] Python 패키지 설치 완료

echo.
echo ── 2/2  Node 패키지 설치 중 ───────────────────
cd /d "%~dp0frontend"
npm install
if errorlevel 1 (
    echo [ERROR] npm install 실패
    pause & exit /b 1
)
echo [OK] Node 패키지 설치 완료

:: ── .env 파일 생성 (없을 때만) ──
if not exist "%~dp0backend\.env" (
    copy "%~dp0backend\.env.example" "%~dp0backend\.env" >nul
    echo.
    echo [INFO] backend\.env 파일이 생성됐습니다.
    echo        ANTHROPIC_API_KEY 를 입력하면 Claude API 심층 분석이 활성화됩니다.
    echo        없으면 폴백 리포트로 동작하므로 필수는 아닙니다.
)

echo.
echo ╔══════════════════════════════════════════════╗
echo ║        설치 완료!  start.bat 을 실행하세요   ║
echo ╚══════════════════════════════════════════════╝
echo.
pause
