# backend/simulation/sim_logger.py
"""
Write a per-simulation log file.

Log location: backend/logs/simulations/sim_{sim_id}_{YYYYMMDD_HHMMSS}.log
Each simulation gets its own file recording steps, commands, output, and results.
"""
from __future__ import annotations
import os
import time
from datetime import datetime

_LOGS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "logs", "simulations")

SEP   = "=" * 70
_STEP = "·" * 70

_STATUS_SUCCESS  = "SUCCESS"
_STATUS_BLOCKED  = "BLOCKED"
_STATUS_INFRA    = "INFRA_ERROR"
_STATUS_DRYRUN   = "DRY-RUN"


def _ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


class SimFileLogger:
    """File handler for a single simulation run."""

    def __init__(self, sim_id: str, scenario_title: str, lab_id: str, total_steps: int):
        os.makedirs(_LOGS_DIR, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"sim_{sim_id}_{stamp}.log"
        self._path = os.path.join(_LOGS_DIR, filename)
        self._f = open(self._path, "w", encoding="utf-8")
        self._start_time = time.time()
        self._step_results: list[str] = []

        self._write_header(sim_id, scenario_title, lab_id, total_steps)

    # ── Public API ─────────────────────────────────────────────────────────────

    def log_step_start(self, step_num: int, total: int, title: str,
                       description: str, mitre: str) -> None:
        self._writelines([
            "",
            _STEP,
            f"[Step {step_num}/{total}]  {title}",
            f"MITRE       : {mitre or 'N/A'}",
            f"Description : {description}",
        ])

    def log_step_command(self, step_num: int, original_cmd: str,
                         exec_cmd: str, output: str) -> None:
        lines = [f"Original cmd: {original_cmd}"]
        if exec_cmd and exec_cmd != original_cmd:
            lines.append(f"Exec cmd    : {exec_cmd}")
        lines.append("Output      :")
        for line in output.splitlines():
            lines.append(f"  {line}")
        self._writelines(lines)

    def log_step_success(self, step_num: int, expected_outcome: str) -> None:
        self._writelines([
            f"Result      : {_STATUS_SUCCESS}",
            f"Expected    : {expected_outcome}",
        ])
        self._step_results.append(_STATUS_SUCCESS)

    def log_step_failed_defense(self, step_num: int, keyword: str,
                                expected_outcome: str) -> None:
        self._writelines([
            f"Result      : {_STATUS_BLOCKED} (keyword: '{keyword}')",
            f"Blocked     : {expected_outcome}",
        ])
        self._step_results.append(_STATUS_BLOCKED)

    def log_step_infra_error(self, step_num: int, output: str) -> None:
        self._writelines([
            f"Result      : {_STATUS_INFRA}",
            f"Error       : {output[:300]}",
        ])
        self._step_results.append(_STATUS_INFRA)

    def log_step_dryrun(self, step_num: int, expected_outcome: str) -> None:
        self._writelines([
            f"Result      : {_STATUS_DRYRUN} (no lab running -- conceptual success)",
            f"Expected    : {expected_outcome}",
        ])
        self._step_results.append(_STATUS_DRYRUN)

    def finalize(self) -> str:
        """Write summary footer, close the file, and return the log path."""
        elapsed = time.time() - self._start_time
        total   = len(self._step_results)
        success = sum(1 for r in self._step_results if r in (_STATUS_SUCCESS, _STATUS_DRYRUN))
        failed  = total - success

        lines = [
            "",
            SEP,
            "Simulation complete",
            f"End time    : {_ts()}",
            f"Duration    : {elapsed:.1f}s",
            f"Step result : {success} succeeded / {failed} failed / {total} total",
            "Step summary:",
        ]
        for i, r in enumerate(self._step_results, 1):
            lines.append(f"  [{i:>2}] {r}")
        lines.append(SEP)

        self._writelines(lines)
        self._f.close()
        return self._path

    # ── Internal ───────────────────────────────────────────────────────────────

    def _write_header(self, sim_id: str, scenario_title: str,
                      lab_id: str, total_steps: int) -> None:
        self._writelines([
            SEP,
            "MalScript Analyzer -- Simulation Execution Log",
            SEP,
            f"SIM ID      : {sim_id}",
            f"Start time  : {_ts()}",
            f"Scenario    : {scenario_title}",
            f"Lab ID      : {lab_id}",
            f"Total steps : {total_steps}",
            SEP,
        ])

    def _writelines(self, lines: list[str]) -> None:
        for line in lines:
            self._f.write(line + "\n")
        self._f.flush()
