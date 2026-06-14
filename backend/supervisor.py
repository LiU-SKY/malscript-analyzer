# backend/supervisor.py
# Single-window supervisor: runs Ollama + FastAPI backend in one CMD window.
# Usage: python supervisor.py
from __future__ import annotations
import os, subprocess, sys, threading, time, signal, socket
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SUPERVISOR] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REQ_FILE = os.path.join(BASE_DIR, "requirements.txt")


def check_and_install_deps() -> None:
    from importlib.metadata import version, PackageNotFoundError  # type: ignore

    # 설치명과 import 명이 다른 패키지 매핑
    IMPORT_ALIAS: dict[str, str] = {
        "python-multipart": "multipart",
        "python-dotenv":    "dotenv",
        "scikit-learn":     "sklearn",
        "pywin32":          "win32api",
    }

    if not os.path.exists(REQ_FILE):
        log.warning(f"requirements.txt not found at {REQ_FILE}")
        return

    missing: list[str] = []
    with open(REQ_FILE) as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            # "pywin32; sys_platform == 'win32'" 처리
            spec = line.split(";")[0].strip()
            marker = line[len(spec):].strip()          # "; sys_platform == ..."
            # 플랫폼 마커가 있는데 현재 플랫폼 미해당이면 건너뜀
            if marker and sys.platform != "win32" and "win32" in marker:
                continue
            pkg = spec.split("==")[0].split(">=")[0].split("<=")[0].split("[")[0].strip()
            try:
                version(pkg)
            except PackageNotFoundError:
                missing.append(spec)   # 버전 포함, 마커 제외한 스펙

    if not missing:
        log.info("All Python dependencies are satisfied.")
        return

    names = ", ".join(m.split("==")[0] for m in missing)
    log.warning(f"Missing packages ({len(missing)}): {names}")
    log.info("Auto-installing via pip -- please wait...")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", "--quiet"] + missing,
        )
        log.info("Dependencies installed successfully.")
    except subprocess.CalledProcessError as e:
        log.error(f"pip install failed (exit {e.returncode})")
        log.error(f"  Manual fix: pip install -r {REQ_FILE}")
        sys.exit(1)


def check_docker_available() -> None:
    try:
        import docker  # noqa: F401
        docker.from_env().ping()
        log.info("Docker daemon: reachable -- Lab environment ready")
    except ImportError:
        log.warning("docker SDK not installed -- will auto-install on first lab request")
    except Exception:
        log.warning(
            "Docker daemon not reachable. "
            "Docker Desktop(Windows/Mac) or Docker Engine(Linux) must be running. "
            "Dry-run simulation works without Docker."
        )


def _is_port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _stream(proc: subprocess.Popen, prefix: str) -> None:
    try:
        for raw in proc.stdout:
            line = raw.decode("utf-8", errors="replace").rstrip()
            if line:
                print(f"[{prefix}] {line}", flush=True)
    except Exception:
        pass


def start_ollama() -> subprocess.Popen | None:
    if _is_port_open(11434):
        log.info("Ollama already running on :11434 -- skipping")
        return None
    log.info("Starting Ollama...")
    try:
        proc = subprocess.Popen(
            ["ollama", "serve"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            creationflags=0,
        )
        t = threading.Thread(target=_stream, args=(proc, "OLLAMA"), daemon=True)
        t.start()
        for _ in range(20):
            if _is_port_open(11434):
                log.info("Ollama ready on :11434")
                return proc
            time.sleep(0.5)
        log.warning("Ollama did not respond within 10s -- continuing anyway")
        return proc
    except FileNotFoundError:
        log.warning("ollama not found -- rule-based fallback mode")
        return None


def start_backend() -> subprocess.Popen:
    log.info("Starting FastAPI backend on :8000 ...")
    env = os.environ.copy()
    # PYTHONUTF8=1: uvicorn 프로세스(+ multiprocessing spawn worker)의 sys.stdout/stderr를
    # UTF-8로 강제한다. 한국어 Windows 로캘 cp949에서 em dash 등을 로그에 쓸 때 발생하는
    # UnicodeEncodeError → StreamHandler 블로킹 → Application startup 미완료 문제 해결.
    env["PYTHONUTF8"] = "1"
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app",
         "--host", "0.0.0.0", "--port", "8000", "--reload"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        cwd=BASE_DIR,
        env=env,
    )
    t = threading.Thread(target=_stream, args=(proc, "BACKEND"), daemon=True)
    t.start()
    return proc


def main() -> None:
    print()
    print("=" * 52)
    print("  MalScript Analyzer -- Single-Window Supervisor")
    print("=" * 52)
    print("  Backend : http://localhost:8000")
    print("  Swagger : http://localhost:8000/docs")
    print("  Press Ctrl+C to stop all services.")
    print("=" * 52)
    print()

    log.info("Checking Python dependencies...")
    check_and_install_deps()
    log.info("Checking Docker availability...")
    check_docker_available()
    print()

    procs: list[subprocess.Popen] = []

    ollama_proc = start_ollama()
    if ollama_proc:
        procs.append(ollama_proc)

    backend_proc = start_backend()
    procs.append(backend_proc)

    def _shutdown(sig, frame):
        log.info("Shutting down...")
        for p in procs:
            try:
                p.terminate()
            except Exception:
                pass
        log.info("All processes terminated.")

    import signal
    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    log.info("Supervisor running. Waiting for processes...")
    for p in procs:
        try:
            p.wait()
        except KeyboardInterrupt:
            _shutdown(None, None)
            break


if __name__ == "__main__":
    main()
