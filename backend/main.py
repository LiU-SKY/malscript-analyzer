# backend/main.py
from __future__ import annotations

# Load .env FIRST before any other imports that read env vars
from dotenv import load_dotenv
import os
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

import asyncio
import json
import logging
import sys
import threading
import uuid
from typing import Annotated, Literal

from fastapi import FastAPI, File, UploadFile, HTTPException, Path, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from pipeline import run_pipeline
from security.schemas import (
    AnalyzeResponse, HealthResponse, AnalysisResult,
    VulnerabilityReport, AttackScenario,
)
from console import get_system_status, subscribe, unsubscribe, WebSocketLogHandler
from os_detector import detect_os
# sandbox_runner 제거 — Windows Sandbox 미사용, Linux/Docker 전용

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)

_ws_handler = WebSocketLogHandler()
_ws_handler.setFormatter(logging.Formatter("%(levelname)s  %(name)s  %(message)s"))
logging.getLogger().addHandler(_ws_handler)

app = FastAPI(
    title="MalScript Analyzer API",
    description="Multi-stage malicious script analysis (Local AI + Claude API)",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_result_cache: dict[str, AnalysisResult] = {}
_scenario_cache: dict[str, AttackScenario] = {}
ALLOWED_EXTENSIONS = {".ps1", ".js", ".py", ".vbs", ".bat", ".sh", ".ts"}
MAX_FILE_SIZE_MB = 2

# ── 캐시 LRU 한도 ──────────────────────────────────────────────────────────────
_CACHE_MAX_RESULTS   = 200   # 초과 시 가장 오래된 항목 삭제
_CACHE_MAX_SCENARIOS = 100

# ── 디스크 영속화 ─────────────────────────────────────────────────────────────
_STORE_DIR = os.path.join(os.path.dirname(__file__), ".cache")
os.makedirs(_STORE_DIR, exist_ok=True)
_RESULTS_FILE   = os.path.join(_STORE_DIR, "results.json")
_SCENARIOS_FILE = os.path.join(_STORE_DIR, "scenarios.json")


def _evict_cache(cache: dict, max_size: int, label: str) -> None:
    """최대 크기 초과 시 가장 오래된 항목 삭제 — Python dict 삽입 순서 보정."""
    overflow = len(cache) - max_size
    if overflow <= 0:
        return
    oldest_keys = list(cache.keys())[:overflow]
    for k in oldest_keys:
        del cache[k]
    logger.info(f"[cache] {label} evicted {overflow} oldest entries (limit={max_size})")


def _repair_truncated_json(raw: str) -> dict:
    """트레일링 콤마 또는 잘린 JSON을 최대한 복구한다."""
    # 1차: 그대로 파싱
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    # 2차: trailing comma + 닫는 } 추가 (가장 흔한 truncation 패턴)
    try:
        fixed = raw.rstrip().rstrip(",") + "}"
        result = json.loads(fixed)
        logger.warning("[cache] repaired truncated JSON (trailing comma removed)")
        return result
    except json.JSONDecodeError:
        pass
    # 3차: 마지막 완성된 key:value 쌍까지만 추출
    try:
        # 완성된 항목들만 찾기: "key": { ... } 패턴을 역순으로 탐색
        last_brace = raw.rfind("},")
        if last_brace > 0:
            truncated = raw[: last_brace + 1] + "}"
            result = json.loads(truncated)
            logger.warning(
                f"[cache] repaired severely truncated JSON, kept {len(result)} entries"
            )
            return result
    except json.JSONDecodeError:
        pass
    raise ValueError("Cannot repair JSON cache file")


def _load_cache() -> None:
    """서버 시작 시 디스크에서 캐시를 복원한다. 손상된 파일도 자가복구 시도."""
    global _result_cache, _scenario_cache
    for fpath, cache, schema, max_size in [
        (_RESULTS_FILE,   _result_cache,   AnalysisResult, _CACHE_MAX_RESULTS),
        (_SCENARIOS_FILE, _scenario_cache, AttackScenario, _CACHE_MAX_SCENARIOS),
    ]:
        if os.path.exists(fpath):
            try:
                with open(fpath, encoding="utf-8") as fh:
                    raw_text = fh.read()
                raw: dict = _repair_truncated_json(raw_text)
                loaded = 0
                for k, v in list(raw.items())[-max_size:]:   # 최신 max_size 개만 복원
                    try:
                        cache[k] = schema.model_validate(v)  # type: ignore[call-arg]
                        loaded += 1
                    except Exception:
                        pass  # 개별 엔트리 손상은 건너뜀
                logger.info(f"[cache] loaded {loaded} entries from {os.path.basename(fpath)}")
                # 복구된 경우 정상 형식으로 재저장
                if raw_text.rstrip() != json.dumps(raw, ensure_ascii=False):
                    _atomic_write(fpath, raw)
                    logger.info(f"[cache] rewrote repaired cache to {os.path.basename(fpath)}")
            except Exception as e:
                logger.warning(f"[cache] failed to load {fpath}: {e}")


def _atomic_write(fpath: str, data: dict) -> None:
    """임시 파일에 쓴 뒤 rename — 프로세스 종료 시 파일 손상 방지."""
    tmp = fpath + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, fpath)   # atomic on same filesystem
    except Exception:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def _save_results() -> None:
    _evict_cache(_result_cache, _CACHE_MAX_RESULTS, "results")
    try:
        _atomic_write(_RESULTS_FILE, {k: v.model_dump() for k, v in _result_cache.items()})
    except Exception as e:
        logger.warning(f"[cache] results save error: {e}")


def _save_scenarios() -> None:
    _evict_cache(_scenario_cache, _CACHE_MAX_SCENARIOS, "scenarios")
    try:
        _atomic_write(_SCENARIOS_FILE, {k: v.model_dump() for k, v in _scenario_cache.items()})
    except Exception as e:
        logger.warning(f"[cache] scenarios save error: {e}")


_load_cache()


@app.on_event("startup")
async def _startup() -> None:
    """서버 시작 시: 이전 세션의 Docker 랩 컨테이너를 백그라운드에서 복원한다.

    fire-and-forget 방식으로 즉시 반환 — 서버 startup을 절대 블로킹하지 않는다.
    복원 결과는 daemon 스레드가 완료되면 로그에 출력된다.
    """
    def _run() -> None:
        # NOTE: logger.info() blocks in uvicorn's multiprocessing worker on Korean
        # Windows (cp949 stdout encoding / pipe issue). Use print(flush=True) here.
        try:
            from docker_mgr import restore_labs_from_docker
            n = restore_labs_from_docker()
            if n:
                print(f"[startup] Restored {n} Docker lab(s)", flush=True)
            else:
                print("[startup] No previous labs to restore", flush=True)
        except Exception as e:
            print(f"[startup] Docker lab restore failed (Docker not running?): {e}", flush=True)

    # daemon=True — killed when uvicorn --reload restarts the worker
    threading.Thread(target=_run, daemon=True, name="docker-restore").start()
    print("[startup] Docker lab restore started in background — server ready", flush=True)


# ── System ────────────────────────────────────────────────────────────────────

@app.get("/health", response_model=HealthResponse, tags=["System"])
async def health_check() -> HealthResponse:
    """헬스체크 — ollama HTTP API를 직접 호출해 3초 타임아웃 안에 응답."""
    import httpx as _hx
    ollama_ok = False
    model_name = "none"
    try:
        async with _hx.AsyncClient(timeout=3.0) as cli:
            r = await cli.get("http://127.0.0.1:11434/api/tags")
            if r.status_code == 200:
                data = r.json()
                models_raw = data.get("models", [])
                names = [m.get("name", "") or m.get("model", "") for m in models_raw]
                names = [n for n in names if n]
                ollama_ok = bool(names)
                model_name = next((n for n in names if "mistral" in n), names[0] if names else "none")
    except Exception:
        pass
    return HealthResponse(status="ok", ollama_available=ollama_ok, model_loaded=model_name)


@app.get("/system/status", tags=["System"])
async def system_status() -> dict:
    import asyncio
    s = await asyncio.to_thread(get_system_status)
    return {
        "cpu_percent": s.cpu_percent,
        "mem_total_mb": s.mem_total_mb,
        "mem_used_mb": s.mem_used_mb,
        "mem_percent": s.mem_percent,
        "disk_total_gb": s.disk_total_gb,
        "disk_used_gb": s.disk_used_gb,
        "disk_percent": s.disk_percent,
        "ollama_running": s.ollama_running,
        "backend_running": s.backend_running,
        "uptime_seconds": s.uptime_seconds,
        "top_processes": [
            {"pid": p.pid, "name": p.name, "cpu": p.cpu_percent, "mem_mb": p.mem_mb}
            for p in s.processes
        ],
    }


# ── WebSocket Console ─────────────────────────────────────────────────────────

@app.websocket("/ws/console/{source}")
async def ws_console(websocket: WebSocket, source: str = "all") -> None:
    await websocket.accept()
    src: Literal["backend", "ollama", "all"] = (
        source if source in ("backend", "ollama", "all") else "all"
    )
    history, q = await subscribe(src)
    try:
        for entry in history:
            await websocket.send_text(json.dumps(entry))
        while True:
            try:
                entry = await asyncio.wait_for(q.get(), timeout=30.0)
                if src == "all" or entry["source"] == src:
                    await websocket.send_text(json.dumps(entry))
            except asyncio.TimeoutError:
                await websocket.send_text(json.dumps({"source": "ping", "line": ""}))
    except WebSocketDisconnect:
        pass
    finally:
        await unsubscribe(q)


# ── Analysis ──────────────────────────────────────────────────────────────────

@app.post("/analyze", response_model=AnalyzeResponse, tags=["Analysis"])
async def analyze_file(
    file: Annotated[UploadFile, File(description="Script file to analyze")],
) -> AnalyzeResponse:
    filename = file.filename or "unknown"
    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=415,
            detail=f"Unsupported extension: {ext}. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}",
        )
    raw_bytes = await file.read()
    if len(raw_bytes) > MAX_FILE_SIZE_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"File too large (max {MAX_FILE_SIZE_MB}MB)")
    if len(raw_bytes) == 0:
        raise HTTPException(status_code=400, detail="Empty file.")

    logger.info(f"[/analyze] file={filename} size={len(raw_bytes)}B")
    try:
        # run_pipeline은 Ollama + Claude API 동기 호출 포함 (수초~수십초)
        # → asyncio.to_thread로 스레드 풀 위임, 이벤트 루프 블로킹 방지
        result = await asyncio.to_thread(run_pipeline, filename, raw_bytes)
    except Exception as e:
        logger.error(f"[/analyze] pipeline error: {e}", exc_info=True)
        return AnalyzeResponse(success=False, error=str(e))

    # OS 타입 감지
    os_info = detect_os(filename, raw_bytes)
    result = result.model_copy(update={
        "target_os":     os_info["target_os"],
        "os_confidence": os_info["confidence"],
        "os_reason":     os_info["reason"],
    })
    logger.info(
        f"[/analyze] OS detected: {os_info['target_os']} "
        f"[{os_info['confidence']}] — {os_info['reason']}"
    )

    result_id = str(uuid.uuid4())[:8]
    _result_cache[result_id] = result
    _save_results()

    # Auto-generate scenario when risk >= MEDIUM (score >= 0.50) and API key is set
    if not result.llm_skipped and os.getenv("ANTHROPIC_API_KEY"):
        try:
            from scenario import generate_scenario
            logger.info(f"[/analyze] risk={result.local.risk_level} >= MEDIUM -> auto-generating scenario")
            scenario = await asyncio.to_thread(generate_scenario, result)
            _scenario_cache[scenario.scenario_id] = scenario
            result = result.model_copy(update={"scenario_id": scenario.scenario_id})
            _result_cache[result_id] = result
            _save_results()
            _save_scenarios()
            logger.info(f"[/analyze] scenario auto-generated | scenario_id={scenario.scenario_id}")
        except Exception as e:
            logger.warning(f"[/analyze] scenario auto-gen failed (non-fatal): {e}")

    logger.info(
        f"[/analyze] done | id={result_id} score={result.local.risk_score:.3f} "
        f"level={result.local.risk_level} llm_skipped={result.llm_skipped} "
        f"scenario_id={result.scenario_id} time={result.processing_time_ms}ms"
    )
    return AnalyzeResponse(success=True, result=result, result_id=result_id)


@app.get("/analyze/{result_id}", response_model=AnalyzeResponse, tags=["Analysis"])
async def get_result(
    result_id: Annotated[str, Path(description="Analysis result ID")],
) -> AnalyzeResponse:
    result = _result_cache.get(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found.")
    return AnalyzeResponse(success=True, result=result, result_id=result_id)


# ── Vulnerability ─────────────────────────────────────────────────────────────

@app.get("/results", tags=["Analysis"])
async def list_results() -> list:
    """분석 결과 목록 (id, filename, risk_level, score, timestamp 요약)."""
    import time as _time
    results = []
    for rid, r in _result_cache.items():
        results.append({
            "result_id": rid,
            "filename": r.filename,
            "lang_hint": r.lang_hint,
            "risk_level": r.local.risk_level,
            "risk_score": round(r.local.risk_score, 3),
            "llm_skipped": r.llm_skipped,
            "scenario_id": r.scenario_id,
            "processing_time_ms": r.processing_time_ms,
        })
    return results


@app.delete("/results/{result_id}", tags=["Analysis"])
async def delete_result(
    result_id: Annotated[str, Path(description="Analysis result ID")],
) -> dict:
    """분석 결과를 캐시 및 디스크에서 삭제한다."""
    if result_id not in _result_cache:
        raise HTTPException(status_code=404, detail="Result not found.")
    del _result_cache[result_id]
    _save_results()
    logger.info(f"[/results] deleted result_id={result_id}")
    return {"deleted": result_id}


@app.get("/vulnerabilities/{result_id}", response_model=VulnerabilityReport, tags=["Vulnerability"])
async def get_vulnerabilities(
    result_id: Annotated[str, Path(description="Analysis result ID")],
) -> VulnerabilityReport:
    result = _result_cache.get(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Result not found.")
    if not result.vulnerabilities:
        raise HTTPException(status_code=404, detail="No vulnerability data for this result.")
    return result.vulnerabilities


# ── Scenario ──────────────────────────────────────────────────────────────────

@app.post("/scenarios/generate", response_model=AttackScenario, tags=["Scenario"])
async def generate_scenario_endpoint(result_id: str) -> AttackScenario:
    result = _result_cache.get(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="Analysis result not found.")
    from scenario import generate_scenario
    logger.info(f"[/scenarios/generate] result_id={result_id}")
    # generate_scenario는 Claude API 동기 HTTP 호출(최대 60초) → to_thread
    scenario = await asyncio.to_thread(generate_scenario, result)
    _scenario_cache[scenario.scenario_id] = scenario
    _save_scenarios()
    logger.info(
        f"[/scenarios/generate] done | scenario_id={scenario.scenario_id} steps={len(scenario.steps)}"
    )
    return scenario


@app.get("/scenarios/{scenario_id}", response_model=AttackScenario, tags=["Scenario"])
async def get_scenario(
    scenario_id: Annotated[str, Path(description="Scenario ID")],
) -> AttackScenario:
    scenario = _scenario_cache.get(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found.")
    return scenario



@app.get("/labs", tags=["Docker Lab"])
async def list_labs_endpoint() -> list:
    """현재 세션에서 생성된 모든 랩 목록을 반환한다."""
    from docker_mgr import list_labs
    return list_labs()


@app.get("/labs/docker-status", tags=["Docker Lab"])
async def get_docker_status() -> dict:
    """Docker 데몬 접근 가능 여부를 빠르게 반환한다."""
    from docker_mgr.docker_manager import docker_status
    # docker_status → _get_client → Docker ping (네트워크 I/O 블로킹)
    return await asyncio.to_thread(docker_status)


@app.get("/labs/presets", tags=["Docker Lab"])
async def list_lab_presets() -> list:
    from docker_mgr import list_presets
    return list_presets()


@app.post("/labs/create/stream", tags=["Docker Lab"])
async def create_lab_stream(preset_name: str):
    """SSE endpoint — streams Docker pull/create progress in real time."""
    import queue, threading
    from docker_mgr.docker_manager import create_lab_streaming

    q: queue.Queue = queue.Queue()

    def emit(event_type: str, message: str) -> None:
        q.put({"event": event_type, "message": message})

    def _run() -> None:
        try:
            create_lab_streaming(preset_name, emit)
        except Exception as e:
            emit("error", str(e).split("\n")[0])
        finally:
            q.put(None)   # sentinel

    threading.Thread(target=_run, daemon=True).start()

    async def generate():
        loop = asyncio.get_running_loop()
        while True:
            item = await loop.run_in_executor(None, q.get)
            if item is None:
                break
            yield f"data: {json.dumps(item, ensure_ascii=False)}\n\n"

    headers = {
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    }
    return StreamingResponse(generate(), media_type="text/event-stream", headers=headers)


@app.post("/labs/create", tags=["Docker Lab"])
async def create_lab_endpoint(preset_name: str, scenario_id: str = "") -> dict:
    from docker_mgr import create_lab
    logger.info(f"[/labs/create] preset={preset_name}")
    try:
        # create_lab는 Docker image pull + run — 수 분 걸릴 수 있음 → to_thread
        lab = await asyncio.to_thread(create_lab, preset_name)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Docker error: {e}")
    return {
        "lab_id": lab.lab_id, "preset_name": lab.preset_name,
        "status": lab.status, "target_ports": lab.target_ports,
        "attacker_container_id": lab.attacker_container_id,
        "target_container_id": lab.target_container_id,
        "error": lab.error,
    }


@app.get("/labs/{lab_id}", tags=["Docker Lab"])
async def get_lab_status(
    lab_id: Annotated[str, Path(description="Lab ID")],
) -> dict:
    from docker_mgr import get_lab
    lab = get_lab(lab_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Lab not found.")
    return {
        "lab_id": lab.lab_id, "preset_name": lab.preset_name,
        "status": lab.status, "target_ports": lab.target_ports,
        "attacker_container_id": lab.attacker_container_id,
        "target_container_id": lab.target_container_id,
        "error": lab.error,
    }


@app.delete("/labs/{lab_id}", tags=["Docker Lab"])
async def stop_lab_endpoint(
    lab_id: Annotated[str, Path(description="Lab ID")],
) -> dict:
    from docker_mgr import stop_lab, get_lab
    if not get_lab(lab_id):
        raise HTTPException(status_code=404, detail="Lab not found.")
    try:
        # stop_lab은 Docker container stop/remove — 블로킹 → to_thread
        lab = await asyncio.to_thread(stop_lab, lab_id)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Docker error: {e}")
    return {"lab_id": lab.lab_id, "status": lab.status}


# \u2500\u2500 Simulation (SSE) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500

@app.get("/simulation/run", tags=["Simulation"])
async def run_simulation_endpoint(scenario_id: str, lab_id: str = "dry-run") -> StreamingResponse:
    scenario = _scenario_cache.get(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found.")
    from simulation import run_simulation
    async def _stream():
        async for chunk in run_simulation(scenario, lab_id):
            yield chunk
    return StreamingResponse(
        _stream(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/simulation/{sim_id}", tags=["Simulation"])
async def get_simulation(
    sim_id: Annotated[str, Path(description="Simulation ID")],
) -> dict:
    from simulation import get_sim
    sim = get_sim(sim_id)
    if not sim:
        raise HTTPException(status_code=404, detail="Simulation not found.")
    return {
        "sim_id": sim.sim_id, "scenario_id": sim.scenario_id,
        "lab_id": sim.lab_id, "status": sim.status,
        "steps_done": sim.steps_done, "steps_total": sim.steps_total,
        "error": sim.error, "event_count": len(sim.events),
    }

# ── Manual Simulation (step-by-step) ─────────────────────────────────────

@app.get("/simulation/defenses/{mitre}", tags=["Simulation"])
async def get_defenses_for_technique(mitre: str) -> list:
    """MITRE technique ID 에 대한 방어 액션 목록을 반환한다."""
    from simulation.defenses import get_defenses
    return get_defenses(mitre)


@app.post("/simulation/defend", tags=["Simulation"])
async def apply_defense(body: dict) -> dict:
    """대상(target) 컨테이너에 방어 액션을 실행한다.

    body: { lab_id, mitre, defense_id }
    """
    lab_id    = body.get("lab_id", "")
    mitre     = body.get("mitre", "")
    defense_id = body.get("defense_id", "")
    if not defense_id:
        raise HTTPException(status_code=400, detail="defense_id 필요")

    from simulation.defenses import get_defense_command, get_defenses
    cmd = get_defense_command(mitre, defense_id)
    if not cmd:
        raise HTTPException(status_code=404, detail=f"방어 액션 '{defense_id}' 없음")

    # 방어 액션 이름 조회
    actions = get_defenses(mitre)
    action_name = next((a["name"] for a in actions if a["id"] == defense_id), defense_id)

    from docker_mgr import exec_in_target, get_lab
    lab = get_lab(lab_id)
    is_dry = not lab or lab.status != "running"

    if is_dry:
        output = f"[DRY-RUN] {cmd[:120]}"
    else:
        import asyncio
        loop = asyncio.get_running_loop()
        output = await loop.run_in_executor(
            None,
            lambda: exec_in_target(lab_id, cmd, label=action_name),
        )

    return {
        "defense_id":   defense_id,
        "defense_name": action_name,
        "output":       output[:400],
        "is_dry_run":   is_dry,
        "success":      not output.startswith("[ERROR]"),
    }


@app.post("/simulation/run-step", tags=["Simulation"])
async def run_single_step(body: dict) -> dict:
    """단일 시뮬레이션 단계를 실행하고 결과를 반환한다.

    body: { scenario_id, step_number, lab_id }
    """
    scenario_id = body.get("scenario_id", "")
    step_number = int(body.get("step_number", 1))
    lab_id      = body.get("lab_id", "dry-run")

    scenario = _scenario_cache.get(scenario_id)
    if not scenario:
        raise HTTPException(status_code=404, detail="Scenario not found.")

    steps = [s for s in scenario.steps if s.step_number == step_number]
    if not steps:
        raise HTTPException(status_code=404, detail=f"Step {step_number} not found.")
    step = steps[0]

    run_cmd = (getattr(step, "exec_command", "") or "").strip() or step.command.strip()

    # Windows 전용 명령어는 DRY-RUN
    win_bins = ("cmd.exe", "powershell.exe", "fltmc", "schtasks",
                "reg.exe", "regsvr32", "mshta", "wscript", "cscript")
    is_win_cmd = any(b in run_cmd.lower() for b in win_bins)

    output = ""
    is_dry = True

    if not run_cmd or is_win_cmd:
        output = f"[DRY-RUN] {run_cmd or '(명령 없음)'}"
    else:
        from docker_mgr import exec_in_attacker, get_lab
        lab = get_lab(lab_id)
        is_dry = not lab or lab.status != "running"
        if is_dry:
            output = f"[DRY-RUN] {run_cmd}"
        else:
            import asyncio
            loop = asyncio.get_running_loop()
            output = await loop.run_in_executor(
                None,
                lambda: exec_in_attacker(
                    lab_id, run_cmd,
                    step_num=step.step_number,
                    mitre=getattr(step, "mitre_technique", ""),
                    title=getattr(step, "title", ""),
                ),
            )

    defense_keywords = ["blocked", "denied", "detected", "permission denied",
                        "access denied", "ids triggered"]
    defense_hit = next((k for k in defense_keywords if k in output.lower()), "")

    return {
        "step_number":     step.step_number,
        "title":           step.title,
        "mitre_technique": getattr(step, "mitre_technique", ""),
        "command":         step.command,
        "exec_command":    getattr(step, "exec_command", ""),
        "output":          output[:500],
        "is_dry_run":      is_dry or output.startswith("[DRY-RUN"),
        "defense_blocked": bool(defense_hit),
        "defense_keyword": defense_hit,
        "expected_outcome": getattr(step, "expected_outcome", ""),
    }



# ── Target Shell WebSocket ────────────────────────────────────────────────────

def _is_attack_blocked(output: str) -> tuple[str, str]:
    """공격 출력에서 방어 차단 여부를 판단한다.
    Returns (status, reason): status = 'blocked'|'success'|'dry_run'|'infra_error'
    """
    if output.startswith("[DRY-RUN"):
        return "dry_run", "DRY-RUN 모드"
    if output.startswith("[ERROR]"):
        return "infra_error", "인프라 오류 (Docker 미실행)"
    out = output.lower()
    checks = [
        ("permission denied",       "권한 거부"),
        ("operation not permitted", "작업 거부"),
        ("command not found",       "명령 없음"),
        ("no such file or directory", "파일 없음"),
        ("cannot execute",          "실행 차단"),
        ("connection refused",      "연결 거부"),
        ("network unreachable",     "네트워크 차단"),
        ("blocked",                 "명시적 차단"),
        ("access denied",           "접근 거부"),
    ]
    for kw, label in checks:
        if kw in out:
            return "blocked", label
    return "success", ""


@app.websocket("/ws/lab/{lab_id}/shell/target")
async def ws_target_shell(websocket: WebSocket, lab_id: str) -> None:
    """타깃(방어) 컨테이너에 대한 인터랙티브 셸 WebSocket.

    클라이언트 → 서버 메시지 형식:
      { "type": "run",    "command": "<bash 명령>" }
      { "type": "verify", "scenario_id": "...", "step_number": 1 }

    서버 → 클라이언트 메시지 형식:
      { "type": "connected",     "is_dry_run": bool, "message": "..." }
      { "type": "output",        "command": "...", "result": "...", "is_dry_run": bool }
      { "type": "verify_result", "status": "blocked|success|dry_run|infra_error",
                                  "reason": "...", "output": "...", "step_title": "..." }
      { "type": "error",         "message": "..." }
    """
    await websocket.accept()
    logger.info("[ws_shell] connected lab_id=%s", lab_id)

    # 연결 직후: 랩 상태 확인 및 초기 메시지 전송
    from docker_mgr import get_lab
    lab = get_lab(lab_id)
    is_dry = not lab or lab.status != "running"
    await websocket.send_json({
        "type": "connected",
        "is_dry_run": is_dry,
        "message": (
            f"[DRY-RUN] Docker 랩 미실행 — 명령어가 시뮬레이션됩니다."
            if is_dry else
            f"[연결됨] 타깃 컨테이너 ({lab.target_container_id[:12] if lab and lab.target_container_id else '?'})"
        ),
    })

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "message": "JSON 파싱 실패"})
                continue

            msg_type = msg.get("type", "run")

            # ── 명령 실행 ──────────────────────────────────────────────────────
            if msg_type == "run":
                command = (msg.get("command") or "").strip()
                if not command:
                    continue

                from docker_mgr import exec_in_target, get_lab as _get_lab
                _lab = _get_lab(lab_id)
                _dry = not _lab or _lab.status != "running"

                loop = asyncio.get_running_loop()
                try:
                    result = await loop.run_in_executor(
                        None,
                        lambda: exec_in_target(
                            lab_id, command,
                            label="defense-shell",
                        ),
                    )
                except Exception as exc:
                    result = f"[ERROR] {exc}"

                await websocket.send_json({
                    "type":       "output",
                    "command":    command,
                    "result":     result[:800],
                    "is_dry_run": _dry or result.startswith("[DRY-RUN"),
                })

            # ── 공격 단계 검증 ─────────────────────────────────────────────────
            elif msg_type == "verify":
                scenario_id = msg.get("scenario_id", "")
                step_number = int(msg.get("step_number", 1))

                scenario = _scenario_cache.get(scenario_id)
                if not scenario:
                    await websocket.send_json({
                        "type": "verify_result", "status": "infra_error",
                        "reason": "시나리오 캐시 없음 — 먼저 시나리오를 로드하세요.",
                        "output": "", "step_title": "",
                    })
                    continue

                step = next((s for s in scenario.steps if s.step_number == step_number), None)
                if not step:
                    await websocket.send_json({
                        "type": "verify_result", "status": "infra_error",
                        "reason": f"단계 {step_number} 없음", "output": "", "step_title": "",
                    })
                    continue

                run_cmd = (getattr(step, "exec_command", "") or "").strip() or step.command.strip()
                if not run_cmd:
                    await websocket.send_json({
                        "type": "verify_result", "status": "dry_run",
                        "reason": "실행 명령 없음 (개념적 단계)",
                        "output": "", "step_title": step.title,
                    })
                    continue

                from docker_mgr import exec_in_attacker, get_lab as _gl2
                _lab2 = _gl2(lab_id)
                _dry2 = not _lab2 or _lab2.status != "running"

                loop = asyncio.get_running_loop()
                try:
                    atk_output = await loop.run_in_executor(
                        None,
                        lambda: exec_in_attacker(
                            lab_id, run_cmd,
                            step_num=step.step_number,
                            mitre=getattr(step, "mitre_technique", ""),
                            title=getattr(step, "title", ""),
                        ),
                    )
                except Exception as exc:
                    atk_output = f"[ERROR] {exc}"

                status, reason = _is_attack_blocked(atk_output)
                # DRY-RUN 상태에서도 'success'/'blocked' 상태 유지 (시뮬레이션 표시용)
                if _dry2 and status not in ("blocked",):
                    status = "dry_run"
                    reason = "DRY-RUN 모드"

                await websocket.send_json({
                    "type":       "verify_result",
                    "status":     status,
                    "reason":     reason,
                    "output":     atk_output[:600],
                    "step_title": step.title,
                })

            else:
                await websocket.send_json({"type": "error", "message": f"알 수 없는 메시지 타입: {msg_type}"})

    except WebSocketDisconnect:
        logger.info("[ws_shell] disconnected lab_id=%s", lab_id)
    except Exception as exc:
        logger.error("[ws_shell] unexpected error: %s", exc, exc_info=True)
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass

@app.websocket("/ws/lab/{lab_id}/shell/attacker")
async def ws_attacker_shell(websocket: WebSocket, lab_id: str) -> None:
    """공격자(Kali) 컨테이너 인터랙티브 셸 WebSocket.

    클라이언트 → 서버:  { "type": "run", "command": "..." }
    서버 → 클라이언트:  { "type": "connected"|"output"|"error", ... }
    """
    await websocket.accept()
    logger.info("[ws_attacker] connected lab_id=%s", lab_id)

    from docker_mgr import exec_in_attacker, get_lab
    lab = get_lab(lab_id)
    is_dry = not lab or lab.status != "running"
    await websocket.send_json({
        "type": "connected",
        "is_dry_run": is_dry,
        "message": (
            "[DRY-RUN] Docker 랩 미실행 — 명령어가 시뮬레이션됩니다."
            if is_dry else
            f"[연결됨] 공격자 컨테이너 ({lab.attacker_container_id[:12] if lab and lab.attacker_container_id else '?'})"
        ),
    })

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "message": "JSON 파싱 실패"})
                continue

            command = (msg.get("command") or "").strip()
            if not command:
                continue

            from docker_mgr import exec_in_attacker as _exec_atk, get_lab as _gl
            _lab = _gl(lab_id)
            _dry = not _lab or _lab.status != "running"

            loop = asyncio.get_running_loop()
            try:
                result = await loop.run_in_executor(
                    None,
                    lambda: _exec_atk(lab_id, command),
                )
            except Exception as exc:
                result = f"[ERROR] {exc}"

            await websocket.send_json({
                "type":       "output",
                "command":    command,
                "result":     result[:800],
                "is_dry_run": _dry or result.startswith("[DRY-RUN"),
            })

    except WebSocketDisconnect:
        logger.info("[ws_attacker] disconnected lab_id=%s", lab_id)
    except Exception as exc:
        logger.error("[ws_attacker] error: %s", exc, exc_info=True)
        try:
            await websocket.send_json({"type": "error", "message": str(exc)})
        except Exception:
            pass


# Windows Sandbox Shell 제거됨 — Linux/Docker 전용으로 전환



# ── Reports ──────────────────────────────────────────────────────────────

from fastapi.responses import Response as FastAPIResponse

@app.get("/reports/generate", tags=["Report"])
async def generate_report_endpoint(
    result_id: str,
    scenario_id: str = "",
    sim_id: str = "",
) -> FastAPIResponse:
    """분석 결과를 한국어 PDF 보고서로 생성합니다."""
    result = _result_cache.get(result_id)
    if not result:
        raise HTTPException(status_code=404, detail="분석 결과를 찾을 수 없습니다.")

    scenario = _scenario_cache.get(scenario_id) if scenario_id else None

    sim_events = None
    sim_summary = None
    if sim_id:
        from simulation import get_sim
        sim = get_sim(sim_id)
        if sim:
            sim_events = [e.__dict__ if hasattr(e, "__dict__") else dict(e) for e in sim.events]
            sim_summary = {
                "total_steps": sim.steps_total,
                "success_count": sum(1 for e in sim.events if getattr(e, "event_type", None) == "step_done"),
                "failed_count": sum(1 for e in sim.events if getattr(e, "event_type", None) in ("step_failed", "defense_triggered")),
                "lab_id": sim.lab_id,
            }

    try:
        from report import generate_report
        pdf_bytes = generate_report(
            result=result,
            scenario=scenario,
            sim_events=sim_events,
            sim_summary=sim_summary,
        )
    except Exception as e:
        logger.error(f"[/reports/generate] PDF generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"PDF generation error: {e}")

    safe_name = result.filename.replace(" ", "_").replace("/", "_")
    filename = f"report_{safe_name}.pdf"
    return FastAPIResponse(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Scenario Debug ────────────────────────────────────────────────────────────

@app.get("/scenarios/debug/env", tags=["Scenario"])
async def debug_scenario_env() -> dict:
    """시나리오 생성 환경 진단 엔드포인트 (URL: /scenarios/debug/env)"""
    import sys, importlib
    
    result = {
        "api_key_set": False,
        "api_key_prefix": "",
        "anthropic_importable": False,
        "httpx_importable": False,
        "scenario_module_ok": False,
        "prompt_loaded": False,
        "test_api_call": "not_attempted",
        "error": "",
    }
    
    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    result["api_key_set"] = bool(api_key)
    result["api_key_prefix"] = api_key[:15] + "..." if len(api_key) > 15 else api_key

    try:
        import anthropic
        result["anthropic_importable"] = True
    except Exception as e:
        result["error"] += f"anthropic: {e}; "

    try:
        import httpx
        result["httpx_importable"] = True
    except Exception as e:
        result["error"] += f"httpx: {e}; "

    try:
        from scenario import scenario_client
        result["scenario_module_ok"] = True
        from scenario.scenario_prompts import SCENARIO_SYSTEM_PROMPT
        result["prompt_loaded"] = bool(SCENARIO_SYSTEM_PROMPT)
    except Exception as e:
        result["error"] += f"scenario: {e}; "

    return result
