# backend/llm_client/claude_client.py
# TOKEN_SAVE: score < 0.5 이면 이 모듈 자체가 호출되지 않음 (pipeline.py)
from __future__ import annotations
import json
import logging
import os
import re

import anthropic

from .prompts import SYSTEM_PROMPT, build_user_prompt, build_local_summary
from security.schemas import LLMReport, MitreTechnique
from security.attack_mapper import enrich_mitre_techniques

logger = logging.getLogger(__name__)

MODEL      = "claude-sonnet-4-6"
MAX_TOKENS = 1200   # TOKEN_SAVE


def call_claude(compressed_code: str, local) -> LLMReport:
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        logger.warning("[claude_client] ANTHROPIC_API_KEY 미설정 → 폴백 리포트 반환")
        return _fallback_report(local)

    client = anthropic.Anthropic(api_key=api_key)
    local_summary = build_local_summary(local)
    user_prompt   = build_user_prompt(compressed_code, local_summary)

    logger.info(f"[claude_client] 호출 | model={MODEL} prompt={len(user_prompt)}chars")

    try:
        response = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_prompt}],
        )
        raw_text   = response.content[0].text.strip()
        token_used = response.usage.input_tokens + response.usage.output_tokens
        logger.info(f"[claude_client] 완료 | tokens={token_used}")
        parsed = _parse_response(raw_text)
        parsed.token_usage = token_used
        parsed.mitre_techniques = enrich_mitre_techniques(parsed.mitre_techniques)
        return parsed

    except anthropic.APIError as e:
        logger.error(f"[claude_client] API 오류: {e}")
        return _fallback_report(local)
    except Exception as e:
        logger.error(f"[claude_client] 예외: {e}", exc_info=True)
        return _fallback_report(local)


def _parse_response(raw: str) -> LLMReport:
    for text in [raw, re.sub(r"```(?:json)?\s*|\s*```", "", raw).strip()]:
        try:
            return _to_report(json.loads(text))
        except json.JSONDecodeError:
            pass
    m = re.search(r"\{[\s\S]*\}", raw)
    if m:
        try:
            return _to_report(json.loads(m.group()))
        except json.JSONDecodeError:
            pass
    return LLMReport(summary="응답 파싱 실패 — 원본을 확인하세요.")


def _to_report(data: dict) -> LLMReport:
    techniques = [
        MitreTechnique(
            technique_id=t.get("technique_id", ""),
            name=t.get("name", ""),
            tactic=t.get("tactic", ""),
        )
        for t in data.get("mitre_techniques", [])
        if isinstance(t, dict)
    ]
    return LLMReport(
        attack_chain=data.get("attack_chain", []),
        mitre_techniques=techniques,
        recommendation=data.get("recommendation", ""),
        summary=data.get("summary", ""),
    )


def _fallback_report(local) -> LLMReport:
    """API 키 없거나 오류 시 로컬 결과 기반 기본 리포트 생성"""
    patterns = ", ".join(local.pattern_labels) if local.pattern_labels else "패턴 없음"
    return LLMReport(
        attack_chain=[
            f"1단계: 의심 스크립트 실행 시도 (위험도 {local.risk_score:.2f})",
            f"2단계: {patterns} 탐지됨",
            "3단계: 추가 페이로드 실행 또는 시스템 접근 시도 가능",
        ],
        mitre_techniques=[],
        recommendation=(
            "해당 스크립트의 실행을 즉시 차단하고 격리된 환경에서만 분석하세요. "
            "스크립트 출처를 확인하고 관련 시스템 로그를 점검하세요."
        ),
        summary=(
            f"위험도 {local.risk_score:.2f}의 의심 스크립트 탐지. "
            f"로컬 분석 결과: {patterns}."
        ),
        token_usage=0,
    )
