# backend/console/system_monitor.py
# System resource monitoring via psutil for GET /system/status
from __future__ import annotations
import time
import threading
import concurrent.futures
from dataclasses import dataclass, field


@dataclass
class ProcessInfo:
    pid: int
    name: str
    cpu_percent: float
    mem_mb: float


@dataclass
class SystemStatus:
    cpu_percent: float
    mem_total_mb: float
    mem_used_mb: float
    mem_percent: float
    disk_total_gb: float
    disk_used_gb: float
    disk_percent: float
    ollama_running: bool
    backend_running: bool
    uptime_seconds: float
    processes: list[ProcessInfo] = field(default_factory=list)


_START_TIME = time.time()

# ── Single-flight cache ───────────────────────────────────────────────────────
# Ensures only ONE psutil scan runs at a time; concurrent callers share result.
_CACHE: tuple[SystemStatus, float] | None = None
_CACHE_TTL = 5.0          # seconds before result is considered stale
_STATUS_LOCK = threading.Lock()

# Persistent thread pool for process scanning (avoids repeated creation cost)
_SCAN_EXECUTOR = concurrent.futures.ThreadPoolExecutor(max_workers=1, thread_name_prefix="sysmon")


def get_system_status() -> SystemStatus:
    global _CACHE

    # Fast path — serve cached value without acquiring any lock
    snap = _CACHE
    if snap is not None and time.time() - snap[1] < _CACHE_TTL:
        return snap[0]

    # Slow path — only one thread computes; others wait then get the cached result
    if not _STATUS_LOCK.acquire(blocking=True, timeout=9):
        return _CACHE[0] if _CACHE else _dummy_status()

    try:
        # Double-check: another thread may have just finished computing
        snap = _CACHE
        if snap is not None and time.time() - snap[1] < _CACHE_TTL:
            return snap[0]

        result = _compute_status()
        _CACHE = (result, time.time())
        return result
    except Exception:
        return _CACHE[0] if _CACHE else _dummy_status()
    finally:
        _STATUS_LOCK.release()


def _process_scan() -> tuple[bool, bool, list[ProcessInfo]]:
    """
    Walk the process list to find ollama/uvicorn and collect top-10 by RSS.
    This is the only call that can be slow on Windows — we run it in a
    dedicated thread with a hard 3-second timeout (see _compute_status).
    """
    try:
        import psutil
    except ImportError:
        return False, True, []

    ollama_running  = False
    backend_running = False
    procs: list[tuple[float, ProcessInfo]] = []

    try:
        for p in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                info = p.info
                name = (info.get('name') or '').lower()

                if 'ollama'   in name:
                    ollama_running  = True
                if 'uvicorn'  in name or 'python' in name:
                    backend_running = True

                mi     = info.get('memory_info')
                mem_mb = round(mi.rss / 1024 / 1024, 1) if mi else 0.0
                procs.append((mem_mb, ProcessInfo(
                    pid=info.get('pid') or 0,
                    name=info.get('name') or '',
                    cpu_percent=0.0,
                    mem_mb=mem_mb,
                )))
            except Exception:
                # NoSuchProcess / AccessDenied / ZombieProcess / TimeoutExpired
                continue
    except Exception:
        pass

    procs.sort(key=lambda x: x[0], reverse=True)
    return ollama_running, backend_running, [pi for _, pi in procs[:10]]


def _compute_status() -> SystemStatus:
    try:
        import psutil
    except ImportError:
        return _dummy_status()

    # ── Lightweight metrics (always fast) ────────────────────────────────────
    # interval=None returns the delta since the last call — no blocking sleep.
    cpu  = psutil.cpu_percent(interval=None)
    mem  = psutil.virtual_memory()
    try:
        disk = psutil.disk_usage('/')
    except Exception:
        disk = None

    # ── Process scan with hard 3-second timeout ───────────────────────────────
    # On Windows, OpenProcess() for certain system processes can hang.
    # We run the scan in an already-warm thread and abandon it after 3 s.
    ollama_running: bool       = False
    backend_running: bool      = True   # if this code runs, backend is alive
    top_procs: list[ProcessInfo] = []

    try:
        future = _SCAN_EXECUTOR.submit(_process_scan)
        ollama_running, _br, top_procs = future.result(timeout=3)
        # _br (backend_running from scan) is ignored; we know we're running
    except concurrent.futures.TimeoutError:
        # Scan took too long — return partial result with no process list
        pass
    except Exception:
        pass

    return SystemStatus(
        cpu_percent=cpu,
        mem_total_mb=round(mem.total  / 1024 / 1024, 1),
        mem_used_mb=round(mem.used   / 1024 / 1024, 1),
        mem_percent=mem.percent,
        disk_total_gb=round(disk.total / 1024 ** 3, 2) if disk else 0.0,
        disk_used_gb=round(disk.used  / 1024 ** 3, 2) if disk else 0.0,
        disk_percent=disk.percent if disk else 0.0,
        ollama_running=ollama_running,
        backend_running=backend_running,
        uptime_seconds=round(time.time() - _START_TIME, 1),
        processes=top_procs,
    )


def _dummy_status() -> SystemStatus:
    return SystemStatus(
        cpu_percent=0.0, mem_total_mb=0, mem_used_mb=0, mem_percent=0,
        disk_total_gb=0, disk_used_gb=0, disk_percent=0,
        ollama_running=False, backend_running=True, uptime_seconds=0,
    )
