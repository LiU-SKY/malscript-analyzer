# backend/docker_mgr/docker_manager.py
from __future__ import annotations
import logging, subprocess, sys, time, uuid
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SDK / OS dependency helpers
# ---------------------------------------------------------------------------
def _ensure_docker_sdk() -> None:
    try:
        import docker  # noqa: F401
    except ImportError:
        logger.warning("[docker_mgr] docker SDK not installed -- installing...")
        pkgs = ["docker==7.1.0"]
        if sys.platform == "win32":
            pkgs.append("pywin32")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet"] + pkgs)
        return
    if sys.platform == "win32":
        try:
            import win32api  # noqa: F401
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--quiet", "pywin32"])


def _is_docker_desktop_running() -> bool:
    """Check whether Docker Desktop process is alive (Windows only)."""
    if sys.platform != "win32":
        return True   # assume running on Linux/Mac
    try:
        out = subprocess.check_output(
            ["tasklist", "/FI", "IMAGENAME eq Docker Desktop.exe", "/NH"],
            stderr=subprocess.DEVNULL, text=True,
        )
        return "Docker Desktop.exe" in out
    except Exception:
        return False


def _try_launch_docker_desktop() -> bool:
    """Attempt to launch Docker Desktop on Windows. Returns True if launched."""
    import os, glob
    candidates = [
        r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
        r"C:\Program Files (x86)\Docker\Docker\Docker Desktop.exe",
    ]
    # also try AppData\Local
    local = os.environ.get("LOCALAPPDATA", "")
    if local:
        candidates.append(os.path.join(local, "Docker", "Docker", "Docker Desktop.exe"))
    for path in candidates:
        if os.path.exists(path):
            subprocess.Popen([path], close_fds=True)
            logger.info(f"[docker_mgr] Launched Docker Desktop: {path}")
            return True
    return False


# 모듈 레벨 Docker 클라이언트 캐시 — 매 호출 새 연결 생성(연결 풀 소진) 방지
_docker_client_cache = None
_docker_client_lock = None

def _get_docker_lock():
    global _docker_client_lock
    import threading
    if _docker_client_lock is None:
        _docker_client_lock = threading.Lock()
    return _docker_client_lock


def _get_client(timeout: int = 5, force_new: bool = False):
    """
    Return a cached Docker client. Re-uses existing connection if healthy.
    On Windows: detects if Docker Desktop is running; if not, tries to launch it.
    """
    global _docker_client_cache
    _ensure_docker_sdk()
    import docker, docker.errors

    # 캐시된 클라이언트가 있고 ping이 통하면 재사용
    with _get_docker_lock():
        if not force_new and _docker_client_cache is not None:
            try:
                _docker_client_cache.ping()
                return _docker_client_cache
            except Exception:
                logger.debug("[docker_mgr] cached client unhealthy, reconnecting...")
                _docker_client_cache = None

    # Windows: check process first to avoid slow timeouts
    if sys.platform == "win32" and not _is_docker_desktop_running():
        logger.warning("[docker_mgr] Docker Desktop is not running -- attempting to launch...")
        launched = _try_launch_docker_desktop()
        if launched:
            logger.info("[docker_mgr] Waiting up to 30s for Docker Desktop to start...")
            for _ in range(30):
                time.sleep(1)
                if _is_docker_desktop_running():
                    time.sleep(5)  # give daemon a moment
                    break
        else:
            raise RuntimeError(
                "Docker Desktop is not installed or not found.\n"
                "Install from: https://www.docker.com/products/docker-desktop"
            )

    attempts = [("default", lambda: docker.from_env())]
    if sys.platform == "win32":
        attempts += [
            ("npipe docker_engine",
             lambda: docker.DockerClient(base_url="npipe:////./pipe/docker_engine", timeout=timeout)),
            ("npipe dockerDesktopLinuxEngine",
             lambda: docker.DockerClient(base_url="npipe:////./pipe/dockerDesktopLinuxEngine", timeout=timeout)),
            ("tcp://localhost:2375",
             lambda: docker.DockerClient(base_url="tcp://localhost:2375", timeout=timeout)),
        ]

    last_err = None
    for name, factory in attempts:
        try:
            client = factory()
            client.ping()
            logger.info(f"[docker_mgr] connected via {name}")
            _docker_client_cache = client   # 캐시 저장
            return client
        except Exception as exc:
            logger.debug(f"[docker_mgr] [{name}] failed: {exc}")
            last_err = exc

    raise RuntimeError(
        "Docker daemon is not reachable after all attempts.\n"
        "1. Make sure Docker Desktop is fully started (whale icon in taskbar).\n"
        "2. Optionally enable: Docker Desktop > Settings > General >\n"
        "   'Expose daemon on tcp://localhost:2375' then Apply & Restart.\n"
        f"Last error: {last_err}"
    )


# ---------------------------------------------------------------------------
# Lab presets
# ---------------------------------------------------------------------------
LAB_PRESETS: dict[str, dict] = {
    # webgoat/webgoat = 현재 공식 OWASP WebGoat 이미지 (port 8080/8090)
    "webgoat-basic": {
        "attacker_image": "kalilinux/kali-last-release",
        "target_image":   "webgoat/webgoat",
        "target_ports":   [8080, 8090],
        "description":    "WebGoat (OWASP) + Kali attacker",
    },
    # ghcr.io/digininja/dvwa = 최신 DVWA 공식 유지 이미지 (port 4280)
    "dvwa-basic": {
        "attacker_image": "kalilinux/kali-last-release",
        "target_image":   "ghcr.io/digininja/dvwa",
        "target_ports":   [4280],
        "description":    "DVWA (Damn Vulnerable Web App) + Kali attacker",
    },
    # metasploitable2 (port 22/80/445), MSF framework attacker
    "metasploitable": {
        "attacker_image": "metasploitframework/metasploit-framework",
        "target_image":   "tleemcjr/metasploitable2",
        "target_ports":   [22, 80, 445],
        "description":    "Metasploitable2 + Metasploit attacker",
    },
    # 가장 가벼운 조합: ubuntu 타겟 + ubuntu 공격자 (빠른 테스트용)
    "lightweight-test": {
        "attacker_image": "ubuntu:22.04",
        "target_image":   "ubuntu:22.04",
        "target_ports":   [22],
        "description":    "Ubuntu x2 (lightweight dry-run test)",
    },
}


@dataclass
class LabEnvironment:
    lab_id:                str
    preset_name:           str
    attacker_container_id: Optional[str]
    target_container_id:   Optional[str]
    target_ports:          list[int]
    status:                str
    error:                 str = ""
    network_id:            Optional[str] = None


_lab_cache: dict[str, LabEnvironment] = {}
_LAB_CACHE_MAX = 50   # 메모리 누수 방지: 최대 50개 랩


def list_labs() -> list[dict]:
    """현재 세션에서 생성된 모든 랩 목록을 반환한다."""
    result = []
    for lab in _lab_cache.values():
        result.append({
            "lab_id": lab.lab_id,
            "preset_name": lab.preset_name,
            "status": lab.status,
            "target_ports": lab.target_ports,
            "attacker_container_id": lab.attacker_container_id,
            "target_container_id": lab.target_container_id,
            "error": lab.error,
        })
    return sorted(result, key=lambda x: x["lab_id"])


def list_presets() -> list[dict]:
    return [
        {"name": k, "description": v["description"],
         "attacker": v["attacker_image"], "target": v["target_image"]}
        for k, v in LAB_PRESETS.items()
    ]


def docker_status() -> dict:
    """Return Docker availability info (used by /labs/docker-status endpoint)."""
    running = _is_docker_desktop_running()
    if not running:
        return {"available": False, "reason": "Docker Desktop is not running"}
    try:
        _ensure_docker_sdk()
        _get_client(timeout=3)
        return {"available": True, "reason": "ok"}
    except Exception as e:
        return {"available": False, "reason": str(e)[:200]}


def _pull_image_with_progress(client, image: str, emit) -> None:
    """Pull a Docker image and emit granular progress events."""
    emit("pull_start", f"이미지 확인 중: {image}")
    layer_done: set[str] = set()
    for ev in client.api.pull(image, stream=True, decode=True):
        status  = ev.get("status", "")
        prog    = ev.get("progressDetail", {})
        layer   = ev.get("id", "")
        if status in ("Pull complete", "Already exists") and layer:
            layer_done.add(layer)
            emit("pull_layer", f"  {layer}: {status}")
        elif status == "Pulling fs layer" and layer:
            pass  # too noisy
        elif "current" in prog and "total" in prog and prog["total"]:
            pct = int(prog["current"] / prog["total"] * 100)
            if pct % 20 == 0:
                emit("pull_progress", f"  {layer}: {pct}%")
        elif status and status not in ("Waiting", "Verifying Checksum",
                                       "Pulling from", "Digest:", "Status:"):
            emit("pull_progress", f"  {status}")
    emit("pull_done", f"이미지 준비 완료: {image}")


def create_lab_streaming(preset_name: str, emit, extra_env: dict | None = None) -> LabEnvironment:
    """
    create_lab with live progress callbacks.
    emit(event_type, message) is called throughout creation.
    This function is blocking -- run it in a thread.
    """
    if preset_name not in LAB_PRESETS:
        raise ValueError(f"Unknown preset: {preset_name}")
    preset = LAB_PRESETS[preset_name]
    lab_id = str(uuid.uuid4())[:8]
    lab = LabEnvironment(
        lab_id=lab_id, preset_name=preset_name,
        attacker_container_id=None, target_container_id=None,
        target_ports=preset["target_ports"], status="creating",
    )
    # 캐시 크기 제한: 가장 오래된 정지/에러 랩 우선 삭제
    _stopped = [k for k, v in _lab_cache.items() if v.status in ("stopped", "error")]
    while len(_lab_cache) >= _LAB_CACHE_MAX and _stopped:
        del _lab_cache[_stopped.pop(0)]
    _lab_cache[lab_id] = lab
    emit("start", f"랩 생성 시작 | lab_id={lab_id} | preset={preset_name}")
    try:
        emit("status", "Docker 데몬 연결 중...")
        client = _get_client()
        emit("status", "Docker 데몬 연결됨")

        # Pull target image
        _pull_image_with_progress(client, preset["target_image"], emit)

        # Pull attacker image (only if different)
        if preset["attacker_image"] != preset["target_image"]:
            _pull_image_with_progress(client, preset["attacker_image"], emit)

        # Create isolated network
        emit("status", "격리 네트워크 생성 중...")
        net = client.networks.create(f"malscript-lab-{lab_id}", driver="bridge")
        lab.network_id = net.id
        emit("status", f"네트워크 생성 완료: malscript-lab-{lab_id}")

        # 공통 레이블 — 재시작 시 컨테이너 복원에 사용
        common_labels = {
            "malscript.lab_id":  lab_id,
            "malscript.preset":  preset_name,
            "malscript.managed": "true",
        }

        # Start target container
        emit("status", f"대상 컨테이너 시작 중: {preset['target_image']}")

        target = client.containers.run(
            preset["target_image"],
            detach=True,
            name=f"malscript-target-{lab_id}",
            network=f"malscript-lab-{lab_id}",
            ports={f"{p}/tcp": None for p in preset["target_ports"]},
            environment=extra_env or {},
            labels={**common_labels, "malscript.role": "target"},
            remove=False,
        )
        lab.target_container_id = target.id[:12]
        emit("status", f"대상 컨테이너 시작됨: {target.id[:12]}")

        # Start attacker container
        emit("status", f"공격자 컨테이너 시작 중: {preset['attacker_image']}")
        attacker = client.containers.run(
            preset["attacker_image"],
            detach=True,
            name=f"malscript-attacker-{lab_id}",
            network=f"malscript-lab-{lab_id}",
            command="sleep infinity",
            cap_add=["NET_ADMIN"],
            labels={**common_labels, "malscript.role": "attacker"},
            remove=False,
        )
        lab.attacker_container_id = attacker.id[:12]
        emit("status", f"공격자 컨테이너 시작됨: {attacker.id[:12]}")

        lab.status = "running"
        _lab_cache[lab_id] = lab
        emit("complete", f"랩 생성 완료 | lab_id={lab_id}")
        logger.info(f"[docker_mgr] lab RUNNING lab_id={lab_id}")
        return lab

    except Exception as e:
        err = str(e).split("\n")[0][:200]
        lab.status = "error"
        lab.error  = err
        _lab_cache[lab_id] = lab
        emit("error", f"랩 생성 실패: {err}")
        logger.error(f"[docker_mgr] create_lab_streaming error: {e}", exc_info=True)
        return lab


def create_lab(preset_name: str) -> LabEnvironment:
    """동기 버전 (non-streaming). 진행 상황은 로거로만 출력."""
    def _emit(event: str, msg: str) -> None:
        logger.info(f"[docker_mgr] [{event}] {msg}")
    return create_lab_streaming(preset_name, _emit)


def get_lab(lab_id: str) -> Optional[LabEnvironment]:
    return _lab_cache.get(lab_id)


def stop_lab(lab_id: str) -> LabEnvironment:
    lab = _lab_cache.get(lab_id)
    if not lab:
        raise ValueError(f"lab {lab_id} not found")
    try:
        client = _get_client()
        for name in [f"malscript-attacker-{lab_id}", f"malscript-target-{lab_id}"]:
            try:
                c = client.containers.get(name)
                c.stop(timeout=5)
                c.remove(force=True)
                logger.info(f"[docker_mgr] stopped/removed container {name}")
            except Exception as e:
                logger.warning(f"[docker_mgr] stop container {name}: {e}")
        try:
            net = client.networks.get(f"malscript-lab-{lab_id}")
            net.remove()
            logger.info(f"[docker_mgr] removed network malscript-lab-{lab_id}")
        except Exception as e:
            logger.warning(f"[docker_mgr] remove network: {e}")
    except Exception as e:
        logger.error(f"[docker_mgr] stop_lab error: {e}")
    lab.status = "stopped"
    _lab_cache[lab_id] = lab
    return lab


# ---------------------------------------------------------------------------
# Exec helpers
# ---------------------------------------------------------------------------

def _build_log_header(step_num: int, mitre: str, title: str, command: str) -> str:
    """Docker Desktop Logs 탭에 표시될 구조화된 헤더 문자열을 반환한다."""
    parts = ["[SIM] " + "=" * 50]
    meta = []
    if step_num:
        meta.append(f"STEP {step_num}")
    if mitre:
        meta.append(mitre)
    if title:
        meta.append(title)
    if meta:
        parts.append("[SIM] " + " | ".join(meta))
    parts.append(f"[SIM] $ {command[:120]}")
    parts.append("[SIM] " + "-" * 50)
    return "\n".join(parts) + "\n"


def _write_to_container_stdout(container, text: str) -> None:
    """컨테이너 PID 1 stdout (/proc/1/fd/1) 에 text 를 기록한다.
    실패해도 예외를 전파하지 않는다."""
    try:
        # printf 를 사용해 개행 등을 정확히 출력; 작은따옴표 이스케이프
        safe = text.replace("\\", "\\\\").replace("'", "'\\''")
        container.exec_run(
            ["sh", "-c", f"printf '%s' '{safe}' >> /proc/1/fd/1 2>/dev/null || true"],
            stdout=False, stderr=False,
            detach=True,
        )
    except Exception as e:
        logger.debug(f"[docker_mgr] _write_to_container_stdout ignored: {e}")


def exec_in_attacker(
    lab_id: str,
    command: str,
    *,
    step_num: int = 0,
    mitre: str = "",
    title: str = "",
) -> str:
    """공격자 컨테이너에서 명령어를 실행하고 출력을 반환한다.

    출력은 Docker Desktop Logs 탭에서도 볼 수 있도록
    컨테이너 PID 1 의 stdout(/proc/1/fd/1)으로 동시에 기록된다.

    Args:
        lab_id:   랩 식별자
        command:  실행할 셸 명령어
        step_num: 시뮬레이션 단계 번호 (로그 헤더용, 선택)
        mitre:    MITRE ATT&CK 기법 ID (로그 헤더용, 선택)
        title:    단계 제목 (로그 헤더용, 선택)
    """
    lab = _lab_cache.get(lab_id)
    if not lab or lab.status != "running":
        return f"[DRY-RUN] {command}"
    try:
        client = _get_client()
        container = client.containers.get(f"malscript-attacker-{lab_id}")

        # ── Docker Desktop Logs 탭에 헤더 기록 ──────────────────────────────
        # PID 1(sleep infinity)의 stdout 이 Docker 로그 드라이버에 연결되어 있으므로
        # /proc/1/fd/1 에 쓰면 Docker Desktop > Containers > Logs 에 나타난다.
        header = _build_log_header(step_num, mitre, title, command)
        _write_to_container_stdout(container, header)

        # 명령 실행 -- tee 로 /proc/1/fd/1 에도 출력 복사
        wrapped = f"( {command} ) 2>&1 | tee /proc/1/fd/1 || true"
        result = container.exec_run(
            ["sh", "-c", wrapped],
            stdout=True, stderr=True,
            demux=False,
        )
        output = result.output or b""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")

        # 풋터 기록
        footer = "[SIM] " + "-" * 50 + "\n"
        _write_to_container_stdout(container, footer)

        return output.strip()[:500]
    except Exception as e:
        logger.warning(f"[docker_mgr] exec_in_attacker error: {e}")
        return f"[ERROR] {e}"


def restore_labs_from_docker() -> int:
    """서버 재시작 후 Docker에 남아있는 이전 세션의 컨테이너를 _lab_cache에 복원한다.

    - malscript.managed=true 레이블이 붙은 컨테이너를 탐색
    - 중지된 컨테이너는 자동으로 재시작
    - attacker + target 쌍이 모두 발견된 경우만 status="running"으로 복원
    - 한쪽만 있으면 status="partial"로 복원 (사용자가 직접 정리 가능)

    반환: 복원된 랩 수
    """
    try:
        client = _get_client(timeout=5)
    except Exception as e:
        logger.warning(f"[docker_mgr] restore_labs: Docker not connected ({e})")
        return 0

    try:
        containers = client.containers.list(
            all=True,
            filters={"label": "malscript.managed=true"},
        )
    except Exception as e:
        logger.warning(f"[docker_mgr] restore_labs: failed to list containers ({e})")
        return 0

    # lab_id 별로 그룹화
    groups: dict[str, dict] = {}
    for c in containers:
        lid  = c.labels.get("malscript.lab_id")
        role = c.labels.get("malscript.role")
        pset = c.labels.get("malscript.preset", "unknown")
        if not lid or role not in ("attacker", "target"):
            continue
        if lid not in groups:
            groups[lid] = {"preset": pset, "attacker": None, "target": None}
        groups[lid][role] = c

    restored = 0
    for lab_id, data in groups.items():
        if lab_id in _lab_cache:
            continue  # 이미 추적 중

        attacker_c = data["attacker"]
        target_c   = data["target"]
        preset_name = data["preset"]
        preset      = LAB_PRESETS.get(preset_name, {})

        # 중지된 컨테이너 재시작 (3초 타임아웃 — 컨테이너 상태 불량 시 hang 방지)
        def _ensure_running(c, role: str) -> bool:
            if c is None:
                return False
            import concurrent.futures as _cf
            def _do() -> bool:
                c.reload()
                if c.status != "running":
                    logger.info(f"[docker_mgr] restore: restarting {role} container (lab={lab_id})")
                    c.start()
                    c.reload()
                return c.status == "running"
            try:
                with _cf.ThreadPoolExecutor(max_workers=1) as ex:
                    return ex.submit(_do).result(timeout=3)
            except _cf.TimeoutError:
                logger.warning(f"[docker_mgr] restore: {role} restart timed out after 3s (lab={lab_id})")
                return False
            except Exception as e:
                logger.warning(f"[docker_mgr] restore: {role} restart failed (lab={lab_id}): {e}")
                return False

        a_ok = _ensure_running(attacker_c, "attacker")
        t_ok = _ensure_running(target_c,   "target")

        # 네트워크 ID 복구
        network_id: str | None = None
        try:
            nets = client.networks.list(names=[f"malscript-lab-{lab_id}"])
            if nets:
                network_id = nets[0].id
        except Exception:
            pass

        status = "running" if (a_ok and t_ok) else "partial"
        lab = LabEnvironment(
            lab_id=lab_id,
            preset_name=preset_name,
            attacker_container_id=attacker_c.id[:12] if attacker_c else None,
            target_container_id=target_c.id[:12]   if target_c   else None,
            target_ports=preset.get("target_ports", []),
            status=status,
            network_id=network_id,
        )
        _lab_cache[lab_id] = lab
        restored += 1
        logger.info(
            f"[docker_mgr] restore: lab={lab_id} preset={preset_name} "
            f"status={status} attacker={a_ok} target={t_ok}"
        )

    if restored:
        logger.info(f"[docker_mgr] restore_labs complete: {restored} lab(s) restored")
    else:
        logger.info("[docker_mgr] restore_labs: no previous labs found")
    return restored


def exec_in_target(
    lab_id: str,
    command: str,
    *,
    label: str = "",
) -> str:
    """대상(target) 컨테이너에서 명령어를 실행하고 출력을 반환한다.
    주로 방어 액션 적용에 사용된다.

    Args:
        lab_id:  랩 식별자
        command: 실행할 셸 명령어
        label:   로그 헤더 레이블 (선택)
    """
    lab = _lab_cache.get(lab_id)
    if not lab or lab.status != "running":
        return f"[DRY-RUN] {command}"
    try:
        client = _get_client()
        container = client.containers.get(f"malscript-target-{lab_id}")

        if label:
            hdr = f"[DEF] {label}\n[DEF] $ {command[:120]}\n[DEF] {'-' * 40}\n"
            _write_to_container_stdout(container, hdr)

        result = container.exec_run(
            ["sh", "-c", command],
            stdout=True, stderr=True,
            demux=False,
        )
        output = result.output or b""
        if isinstance(output, bytes):
            output = output.decode("utf-8", errors="replace")

        if label:
            _write_to_container_stdout(container, f"[DEF] {chr(39)}{'-' * 40}{chr(39)}\n")

        return output.strip()[:500]
    except Exception as e:
        logger.warning(f"[docker_mgr] exec_in_target error: {e}")
        return f"[ERROR] {e}"
