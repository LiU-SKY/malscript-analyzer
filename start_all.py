# start_all.py — MalScript Analyzer single-window launcher
# Runs backend (supervisor.py) + frontend (npm run dev) in ONE terminal,
# with color-prefixed interleaved output.
from __future__ import annotations
import locale, os, subprocess, sys, threading, time

# 시스템 기본 인코딩 (한국어 Windows = cp949, 대부분의 Linux/Mac = utf-8)
_SYS_ENC = locale.getpreferredencoding(False) or "cp949"
# Windows 여부
_IS_WIN = sys.platform == "win32"

ROOT = os.path.dirname(os.path.abspath(__file__))

# ANSI colors
CYAN   = "\033[96m"
PURPLE = "\033[35m"
BLUE   = "\033[34m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
GRAY   = "\033[90m"
RED    = "\033[91m"
RESET  = "\033[0m"


def enable_ansi_windows() -> None:
    """Enable ANSI escape codes on Windows 10+ consoles."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32   # type: ignore[attr-defined]
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        pass


def _decode(raw: bytes) -> str:
    """UTF-8 우선 디코드, 실패 시 시스템 기본 인코딩(cp949 등) fallback.

    chcp 65001 설정 후에도 일부 Windows 도구는 cp949 바이트를 섞어 출력하므로
    per-line fallback을 유지한다.
    """
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        fallback = "cp949" if _IS_WIN else _SYS_ENC
        return raw.decode(fallback, errors="replace")


def stream_output(proc: subprocess.Popen, prefix: str, color: str) -> None:
    """Forward a process's stdout+stderr lines to our terminal with a prefix."""
    assert proc.stdout is not None
    try:
        for raw in iter(proc.stdout.readline, b""):
            line = _decode(raw).rstrip("\r\n")
            if line:
                print(f"{color}[{prefix}]{RESET} {line}", flush=True)
    except Exception:
        pass


def kill_tree(pid: int) -> None:
    """Kill a process and all its children (Windows taskkill /T)."""
    try:
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
        )
    except Exception:
        pass


def kill_port(port: int) -> None:
    """Kill any process currently listening on *port* (prevents 'address in use')."""
    try:
        result = subprocess.run(
            ["netstat", "-ano"],
            capture_output=True, text=True,
        )
        for line in result.stdout.splitlines():
            if f":{port} " in line and "LISTENING" in line:
                parts = line.split()
                pid = parts[-1]
                if pid.isdigit() and int(pid) != os.getpid():
                    subprocess.run(
                        ["taskkill", "/F", "/PID", pid],
                        capture_output=True,
                    )
    except Exception:
        pass


def main() -> None:
    enable_ansi_windows()

    print(f"\n{CYAN}{'='*54}{RESET}")
    print(f"{CYAN}   MalScript Analyzer — Starting All Services{RESET}")
    print(f"{CYAN}{'='*54}{RESET}\n")

    backend_dir  = os.path.join(ROOT, "backend")
    frontend_dir = os.path.join(ROOT, "frontend")

    # ── 0. Clear stale processes on known ports ──────────────
    print(f"{GRAY}[0/2] Clearing stale processes on ports 8000/3000 ...{RESET}")
    kill_port(8000)
    kill_port(3000)
    time.sleep(0.5)

    # ── 1. Backend ──────────────────────────────────────────
    print(f"{YELLOW}[1/2]{RESET} Starting backend (Ollama + FastAPI) ...")
    # PYTHONUTF8=1 을 supervisor → uvicorn → worker 전 파이프 체인에 전달.
    # 한국어 Windows 기본 로캘(cp949)에서 한글 로그가 깨지는 문제 해결.
    _backend_env = os.environ.copy()
    _backend_env["PYTHONUTF8"] = "1"
    backend = subprocess.Popen(
        [sys.executable, "supervisor.py"],
        cwd=backend_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=_backend_env,
    )

    # Give the backend a moment to boot before Next.js starts
    time.sleep(2)

    # ── 2. Frontend ─────────────────────────────────────────
    print(f"{YELLOW}[2/2]{RESET} Starting frontend (Next.js) ...")
    # Windows에서 npm(Node.js)은 시스템 기본 코드페이지(cp949)로 출력한다.
    # chcp 65001로 UTF-8 코드페이지를 먼저 설정하면 npm 출력도 UTF-8이 된다.
    _npm_cmd = "chcp 65001 > nul && npm run dev" if _IS_WIN else "npm run dev"
    frontend = subprocess.Popen(
        _npm_cmd,
        cwd=frontend_dir,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        shell=True,
    )

    print(f"\n{GREEN}  Frontend : http://localhost:3000{RESET}")
    print(f"{GREEN}  Backend  : http://localhost:8000{RESET}")
    print(f"{GREEN}  Swagger  : http://localhost:8000/docs{RESET}")
    print(f"\n{GRAY}  Ctrl+C to stop all services{RESET}")
    print(f"{CYAN}{'='*54}{RESET}\n")

    # Stream both process outputs in background threads
    threading.Thread(
        target=stream_output, args=(backend, "Backend ", PURPLE), daemon=True
    ).start()
    threading.Thread(
        target=stream_output, args=(frontend, "Frontend", BLUE), daemon=True
    ).start()

    # ── Monitor: exit if either process dies unexpectedly ───
    try:
        while True:
            if backend.poll() is not None:
                print(
                    f"\n{RED}[!] Backend exited (code {backend.returncode}). "
                    f"Stopping frontend...{RESET}"
                )
                kill_tree(frontend.pid)
                break
            if frontend.poll() is not None:
                print(
                    f"\n{RED}[!] Frontend exited (code {frontend.returncode}). "
                    f"Stopping backend...{RESET}"
                )
                kill_tree(backend.pid)
                break
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{YELLOW}  Ctrl+C — stopping all services ...{RESET}")
        kill_tree(backend.pid)
        kill_tree(frontend.pid)
        # Wait briefly for clean shutdown
        for proc in (backend, frontend):
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        print(f"{GREEN}  All services stopped.{RESET}\n")


if __name__ == "__main__":
    main()
