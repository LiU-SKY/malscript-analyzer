# backend/simulation/sim_engine.py
from __future__ import annotations
import asyncio, json, logging, time, uuid
from dataclasses import dataclass, field
from typing import AsyncIterator, Optional

from .sim_logger import SimFileLogger

logger = logging.getLogger(__name__)


@dataclass
class SimEvent:
    event_type: str
    step: int = 0
    message: str = ""
    detail: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_sse(self) -> str:
        data = json.dumps({
            "event_type": self.event_type,
            "step": self.step,
            "message": self.message,
            "detail": self.detail,
            "timestamp": self.timestamp,
        })
        return f"data: {data}\n\n"


@dataclass
class SimResult:
    sim_id: str
    scenario_id: str
    lab_id: str
    status: str
    steps_done: int = 0
    steps_total: int = 0
    events: list[SimEvent] = field(default_factory=list)
    error: str = ""


_sim_cache: dict[str, SimResult] = {}
_SIM_CACHE_MAX = 50   # 최대 50개 시뮬레이션 결과 유지


async def run_simulation(scenario, lab_id: str) -> AsyncIterator[str]:
    sim_id = str(uuid.uuid4())[:8]
    total  = len(scenario.steps)
    result = SimResult(
        sim_id=sim_id, scenario_id=scenario.scenario_id,
        lab_id=lab_id, status="running", steps_total=total,
    )
    # 크기 제한: 가장 오래된 항목 삭제
    overflow = len(_sim_cache) - _SIM_CACHE_MAX + 1
    if overflow > 0:
        for _k in list(_sim_cache.keys())[:overflow]:
            del _sim_cache[_k]
        logger.info(f"[simulation] sim_cache evicted {overflow} oldest entries")
    _sim_cache[sim_id] = result

    logger.info(f'[simulation] START sim_id={sim_id} scenario="{scenario.title}" lab={lab_id} steps={total}')

    # ── 파일 로거 시작 ────────────────────────────────────────────────────────
    sim_log = SimFileLogger(sim_id, scenario.title, lab_id, total)

    start_evt = SimEvent(
        event_type="log",
        message=f"시뮬레이션 시작 (sim_id={sim_id})",
        detail=f"scenario={scenario.title} | lab={lab_id} | steps={total}",
    )
    result.events.append(start_evt)
    yield start_evt.to_sse()

    for step in scenario.steps:
        result.steps_done = step.step_number - 1
        logger.info(f"[simulation] STEP {step.step_number}/{total}  {step.title}  [{step.mitre_technique}]")

        # step_start
        evt_start = SimEvent(
            event_type="step_start", step=step.step_number,
            message=f"[{step.step_number}/{total}] {step.title}",
            detail=step.description,
        )
        result.events.append(evt_start)
        yield evt_start.to_sse()

        # 파일 로그 — 단계 시작
        sim_log.log_step_start(
            step.step_number, total, step.title,
            step.description, step.mitre_technique or "",
        )

        # MITRE log
        if step.mitre_technique:
            evt_m = SimEvent(event_type="log", step=step.step_number,
                             message=f"MITRE: {step.mitre_technique}", detail=step.command or "")
            result.events.append(evt_m)
            yield evt_m.to_sse()

        # Execute
        output = await _exec_step(lab_id, step)
        await asyncio.sleep(0.3)

        # Command log — exec_command(실행됨) vs command(원본 표시)
        exec_cmd_used = getattr(step, "exec_command", "").strip() or step.command.strip()
        if step.command:
            display = f"$ {step.command}"
            if getattr(step, "exec_command", "").strip() and step.exec_command != step.command:
                display += f"  →  (exec) {step.exec_command[:120]}"
            evt_cmd = SimEvent(event_type="log", step=step.step_number,
                               message=display, detail=output[:300])
            result.events.append(evt_cmd)
            yield evt_cmd.to_sse()
            logger.info(f"[simulation]   cmd: {step.command[:80]}")
            logger.info(f"[simulation]   out: {output[:120]}")

            # 파일 로그 — 명령·출력
            sim_log.log_step_command(
                step.step_number,
                step.command,
                getattr(step, "exec_command", "").strip(),
                output,
            )

        # ── Infrastructure/exec 오류는 방어 판정 제외 ────────────────────────
        # [DRY-RUN]  : Docker 랩 미실행 또는 Windows 전용 명령어 → 개념적 성공
        # [ERROR]    : Docker exec 실제 오류 → 인프라 실패
        is_dry_run = output.startswith("[DRY-RUN")   # "[DRY-RUN]" 또는 "[DRY-RUN/Windows]"
        is_real_error = (
            output.startswith("[ERROR]")
            or "executable file not found" in output
            or "OCI runtime exec failed" in output
            or "no such file or directory" in output.lower()
        )
        is_infra_error = is_dry_run or is_real_error

        if is_infra_error:
            if is_dry_run:
                # Docker 미실행 또는 Windows 명령어 → lab_id 와 무관하게 개념적 성공 처리
                evt_done = SimEvent(
                    event_type="step_done", step=step.step_number,
                    message=f"[DRY-RUN] {step.expected_outcome}",
                    detail="Docker 랩 미실행 — 개념적 성공 처리",
                )
                result.events.append(evt_done)
                yield evt_done.to_sse()
                logger.info(f"[simulation] STEP {step.step_number} DRY-RUN SUCCESS")
                sim_log.log_step_dryrun(step.step_number, step.expected_outcome)
            else:
                # 실제 Docker exec 오류 → 인프라 실패 (방어 아님)
                logger.warning(f"[simulation] STEP {step.step_number} INFRA-FAIL: {output[:80]}")
                evt_env = SimEvent(
                    event_type="step_error", step=step.step_number,
                    message=f"실행 환경 오류 — {step.title}",
                    detail=output[:300],
                )
                result.events.append(evt_env)
                yield evt_env.to_sse()

                evt_fail = SimEvent(
                    event_type="step_failed", step=step.step_number,
                    message=f"실행 불가 — {step.title} (Docker 오류)",
                    detail=f"Docker exec 오류: {output[:200]}",
                )
                result.events.append(evt_fail)
                yield evt_fail.to_sse()
                sim_log.log_step_infra_error(step.step_number, output)

        else:
            # 정상 출력 — 방어 키워드 검사
            defense_hit = _check_defenses(output, scenario.defenses)
            if defense_hit:
                logger.warning(f'[simulation] DEFENSE TRIGGERED step={step.step_number} keyword="{defense_hit}" -> BLOCKED')

                evt_def = SimEvent(
                    event_type="defense_triggered", step=step.step_number,
                    message=f"방어 메커니즘 동작: {defense_hit}",
                    detail=output[:200],
                )
                result.events.append(evt_def)
                yield evt_def.to_sse()

                evt_fail = SimEvent(
                    event_type="step_failed", step=step.step_number,
                    message=f"공격 차단됨 — {step.title} 실패",
                    detail=f"방어 키워드: '{defense_hit}'  |  달성 불가: {step.expected_outcome}",
                )
                result.events.append(evt_fail)
                yield evt_fail.to_sse()
                logger.warning(f"[simulation] STEP {step.step_number} FAILED (blocked by '{defense_hit}')")
                sim_log.log_step_failed_defense(step.step_number, defense_hit, step.expected_outcome)
            else:
                evt_done = SimEvent(
                    event_type="step_done", step=step.step_number,
                    message=step.expected_outcome, detail=output[:300],
                )
                result.events.append(evt_done)
                yield evt_done.to_sse()
                logger.info(f"[simulation] STEP {step.step_number} SUCCESS  outcome: {step.expected_outcome[:60]}")
                sim_log.log_step_success(step.step_number, step.expected_outcome)

    result.steps_done = total
    result.status = "complete"
    logger.info(f"[simulation] COMPLETE sim_id={sim_id} steps={total}")

    log_path = sim_log.finalize()
    logger.info(f"[simulation] log saved: {log_path}")

    yield SimEvent(
        event_type="complete", step=total,
        message="시뮬레이션 완료",
        detail=f"steps={result.steps_done} | sim_id={sim_id}",
    ).to_sse()


async def _exec_step(lab_id: str, step) -> str:
    # exec_command 우선: Docker Linux에서 실제 실행 가능한 명령어
    # command 는 표시용 원본 (Windows 네이티브 등)
    run_cmd = getattr(step, "exec_command", "").strip() or step.command.strip()

    if not run_cmd:
        return "(명령 없음 — 개념적 단계)"

    # exec_command가 없고 command만 있는 경우, Windows 명령어 여부 감지
    if not getattr(step, "exec_command", "").strip():
        win_bins = ("cmd.exe", "powershell.exe", "powershell ", "fltmc", "schtasks",
                    "reg.exe", "regsvr32", "mshta", "wscript", "cscript",
                    "rundll32", "certutil", "bitsadmin")
        cmd_lower = run_cmd.lower()
        if any(b in cmd_lower for b in win_bins) or cmd_lower.startswith("if ") or cmd_lower.startswith("if/"):
            logger.info(f"[simulation] _exec_step: Windows command detected (no exec_command) -> DRY-RUN")
            return f"[DRY-RUN/Windows] {run_cmd}"

    try:
        from docker_mgr import exec_in_attacker, get_lab
        lab = get_lab(lab_id)
        if lab and lab.status == "running":
            loop = asyncio.get_running_loop()
            output: str = await loop.run_in_executor(
                None, exec_in_attacker, lab_id, run_cmd
            )
            return output or "(no output)"
        else:
            return f"[LAB NOT RUNNING] {run_cmd}"
    except ImportError:
        return f"[DOCKER UNAVAILABLE] {run_cmd}"
    except Exception as e:
        logger.warning(f"[simulation] _exec_step error: {e}")
        return f"[ERROR] {e}"
