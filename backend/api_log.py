# backend/api_log.py
# Claude API 요청/응답 원본을 backend/api_logs/ 폴더에 JSON 파일로 저장한다.
from __future__ import annotations

import json, logging, os, traceback
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

_LOG_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "api_logs")
os.makedirs(_LOG_DIR, exist_ok=True)


_MAX_LOG_FILES = 200   # 이 수를 초과하면 오래된 파일 삭제


def _prune_log_dir() -> None:
    """api_logs/ 파일 수가 _MAX_LOG_FILES 초과 시 오래된 파일 삭제."""
    try:
        files = sorted(
            (f for f in os.listdir(_LOG_DIR) if f.endswith(".json")),
        )  # 파일명이 타임스탬프 기반이므로 이름순 = 시간순
        excess = len(files) - _MAX_LOG_FILES
        if excess > 0:
            for fname in files[:excess]:
                try:
                    os.remove(os.path.join(_LOG_DIR, fname))
                except OSError:
                    pass
            logger.debug("[api_log] pruned %d old log files", excess)
    except Exception as e:
        logger.debug("[api_log] prune error: %s", e)


def save(
    *,
    call_type: str,          # "scenario" | "llm_analysis"
    model: str,
    system_prompt: str,
    user_prompt: str,
    raw_response: str | None   = None,
    tokens_in: int             = 0,
    tokens_out: int            = 0,
    success: bool              = False,
    parse_ok: bool | None      = None,   # None = N/A
    error: str | None          = None,
    extra: dict | None         = None,
) -> str:
    """API 호출 결과를 JSON 파일로 저장하고 파일 경로를 반환한다."""
    now    = datetime.now(timezone.utc)
    stamp  = now.strftime("%Y%m%d_%H%M%S_%f")[:-3]   # milliseconds
    status = "ok" if success else "fail"
    fname  = f"{stamp}_{call_type}_{status}.json"
    fpath  = os.path.join(_LOG_DIR, fname)

    payload: dict = {
        "timestamp":     now.isoformat(),
        "call_type":     call_type,
        "model":         model,
        "success":       success,
        "parse_ok":      parse_ok,
        "tokens_in":     tokens_in,
        "tokens_out":    tokens_out,
        "tokens_total":  tokens_in + tokens_out,
        "error":         error,
        "request": {
            "system_prompt": system_prompt,
            "user_prompt":   user_prompt,
        },
        "response": {
            "raw": raw_response,
        },
    }
    if extra:
        payload["extra"] = extra

    try:
        with open(fpath, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False, indent=2)
        logger.info("[api_log] saved -> %s", fname)
    except Exception as exc:
        logger.warning("[api_log] save failed: %s", exc)

    # 저장 후 오래된 파일 정리 (비동기 불필요 — 매우 빠른 파일 목록 조회)
    _prune_log_dir()

    return fpath
