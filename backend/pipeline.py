# backend/pipeline.py
# TOKEN_SAVE: 로컬 모델 점수 < 0.5 이면 Claude API 호출을 완전히 건너뜀
from __future__ import annotations
import time
import logging

from preprocessor import preprocess, compress_for_llm
from local_model.risk_scorer import ensemble_score
from security.schemas import (
    AnalysisResult, LocalModelOutput, LLMReport,
    MitreTechnique, RiskLevel
)

logger = logging.getLogger(__name__)

try:
    from llm_client.claude_client import call_claude
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False
    logger.warning("llm_client 미설치 → LLM 기능 비활성")


def run_pipeline(filename: str, raw_bytes: bytes) -> AnalysisResult:
    """
    전체 분석 파이프라인 오케스트레이터

    흐름:
        전처리 → 로컬 AI (병렬) → TOKEN_SAVE 판단 → [Claude API] → 결과 반환

    TOKEN_SAVE 포인트:
        · score < 0.50 → Claude API 호출 SKIP (저위험 파일 100% 절감)
        · 고위험이더라도 압축본(2,000자)만 LLM에 전달 → ~65% 절감
    """
    t_start = time.perf_counter()

    # ── 1. 전처리 ──────────────────────────────────────────────────────────
    # 인코딩 감지 · BOM 제거 · 개행 정규화 · MAX_CHARS=8,000 초과 시 잘라냄
    prep = preprocess(raw_bytes, filename)
    logger.info(f"[pipeline] 전처리 완료 | lang={prep.lang_hint} lines={prep.line_count}")

    # ── 2. 로컬 모델 앙상블 ────────────────────────────────────────────────
    # Ollama Mistral-7B (분류) + 규칙 기반 엔진 (난독화) 병렬 실행
    # 역할: 빠른 1차 필터링 → 불필요한 Claude API 호출 차단 (게이트키퍼)
    local = ensemble_score(prep.cleaned_code, prep.lang_hint)
    logger.info(f"[pipeline] 로컬 분석 완료 | score={local.risk_score:.3f} level={local.risk_level}")

    # ── 3. API 스키마 변환 ─────────────────────────────────────────────────
    risk_level = _to_risk_level(local.risk_score)
    obf = local.obfuscation_result

    local_output = LocalModelOutput(
        risk_score=local.risk_score,
        risk_level=risk_level,
        pattern_labels=local.pattern_labels,
        obfuscation_techniques=local.obfuscation_techniques,
        obfuscation_score=obf.score if obf else 0.0,
        entropy=obf.entropy if obf else 0.0,
        evidence=local.evidence,
        llm_required=local.llm_required,
    )

    # ── 4. TOKEN_SAVE 판단 게이트 ──────────────────────────────────────────
    # score < 0.50 → 로컬 결과만 반환 (Claude API 비용 제로)
    # score ≥ 0.50 → 압축본(compress_for_llm)만 Claude에 전달 → ~65% 절감
    llm_report: LLMReport | None = None
    llm_skipped = not local.llm_required

    if local.llm_required and LLM_AVAILABLE:
        logger.info("[pipeline] score >= 0.5 → Claude API 호출 (claude-sonnet-4-6)")
        # TOKEN_SAVE: 전체 코드 대신 압축본(최대 2,000자)만 전달
        compressed = compress_for_llm(prep.cleaned_code, local.evidence)
        llm_report = call_claude(compressed, local_output)
    elif local.llm_required and not LLM_AVAILABLE:
        logger.warning("[pipeline] LLM 미설정 → SKIP (폴백 리포트 없음)")
        llm_skipped = True
    else:
        # TOKEN_SAVE: 저위험 파일 — Claude API 완전 생략
        logger.info(f"[pipeline] TOKEN_SAVE: score={local.risk_score:.3f} < 0.5 → Claude API 생략")

    elapsed_ms = int((time.perf_counter() - t_start) * 1000)

    return AnalysisResult(
        filename=filename,
        file_size_bytes=prep.original_length,
        lang_hint=prep.lang_hint,
        line_count=prep.line_count,
        truncated=prep.truncated,
        local=local_output,
        llm=llm_report,
        llm_skipped=llm_skipped,
        processing_time_ms=elapsed_ms,
    )


def _to_risk_level(score: float) -> RiskLevel:
    if score >= 0.90: return RiskLevel.CRITICAL
    if score >= 0.75: return RiskLevel.HIGH
    if score >= 0.50: return RiskLevel.MEDIUM
    return RiskLevel.SAFE
