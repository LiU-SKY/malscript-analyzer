@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo.
echo ╔══════════════════════════════════════════════╗
echo ║        MalScript Analyzer — 서버 시작        ║
echo ╚══════════════════════════════════════════════╝
echo.

:: ── 설치 확인 ──
if not exist "%~dp0backend\requirements.txt" (
    echo [ERROR] 프로젝트 폴더 구조가 올바르지 않습니다.
    pause & exit /b 1
)

:: ── Ollama 시작 (설치된 경우) ──
ollama --version >nul 2>&1
if not errorlevel 1 (
    echo [1/3] Ollama 서버 시작 중...
    start "Ollama Server" cmd /k "ollama serve"
    timeout /t 2 /nobreak >nul
    echo [OK] Ollama 창 열림 (mistral 모델 없으면: ollama pull mistral)
) else (
    echo [SKIP] Ollama 미설치 — 규칙 기반 폴백으로 동작합니다.
)

echo.
echo [2/3] FastAPI 백엔드 시작 중...
echo       http://localhost:8000  ^|  Swagger: http://localhost:8000/docs
start "MalScript Backend" cmd /k "cd /d %~dp0backend && python main.py"
timeout /t 3 /nobreak >nul

echo.
echo [3/3] Next.js 프론트엔드 시작 중...
echo       http://localhost:3000
start "MalScript Frontend" cmd /k "cd /d %~dp0frontend && npm run dev"

echo.
echo ╔══════════════════════════════════════════════╗
echo ║  모든 서비스가 시작됐습니다!                 ║
echo ║                                              ║
echo ║  백엔드  : http://localhost:8000             ║
echo ║  프론트  : http://localhost:3000             ║
echo ║  Swagger : http://localhost:8000/docs        ║
echo ╚══════════════════════════════════════════════╝
echo.
echo  잠시 후 브라우저에서 http://localhost:3000 을 열어주세요.
echo  (프론트엔드 첫 빌드는 30초 이상 걸릴 수 있습니다)
echo.
pause
