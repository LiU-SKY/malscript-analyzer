# backend/local_model/risk_scorer.py
# TOKEN_SAVE: 앙상블 점수 < 0.5 이면 Claude API 호출 자체를 차단하는 게이트키퍼
from __future__ import annotations
import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from .classifier import ClassifierResult, classify
from .obfuscation import ObfuscationResult, detect

logger = logging.getLogger(__name__)

# ── 위험도 임계값 ───────────────────────────────────────────────────────────
# TOKEN_SAVE: score < RISK_THRESHOLD_LLM 이면 Claude API 호출 SKIP
RISK_THRESHOLD_LLM      = 0.50   # Claude API 호출 여부 기준 (SAFE ↔ MEDIUM 경계)
RISK_THRESHOLD_HIGH     = 0.75   # HIGH 판정 기준
RISK_THRESHOLD_CRITICAL = 0.90   # CRITICAL 판정 기준

# ── 앙상블 가중치 ──────────────────────────────────────────────────────────
# 최종_점수 = 분류_신뢰도 × 0.65 + 난독화_점수 × 0.35
WEIGHT_CLASSIFIER  = 0.65   # Ollama Mistral-7B 의미론적 분류
WEIGHT_OBFUSCATION = 0.35   # 규칙 기반 난독화 탐지


@dataclass
class LocalModelResult:
    risk_score: float
    risk_level: str
    llm_required: bool
    pattern_labels: list[str] = field(default_factory=list)
    obfuscation_techniques: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    classifier_result: ClassifierResult | None = None
    obfuscation_result: ObfuscationResult | None = None


def ensemble_score(code: str, lang_hint: str = "Unknown") -> LocalModelResult:
    """로컬 모델 병렬 실행 후 앙상블 합산 → TOKEN_SAVE 여부 결정"""
    # 분류기 + 난독화 탐지기 병렬 실행
    with ThreadPoolExecutor(max_workers=2) as pool:
        clf_future = pool.submit(classify, code, lang_hint)
        obf_future = pool.submit(detect, code)
        clf: ClassifierResult = clf_future.result()
        obf: ObfuscationResult = obf_future.result()

    # TOKEN_SAVE: 앙상블 점수 계산 — 낮으면 LLM 호출 차단
    final_score = round(
        clf.confidence * WEIGHT_CLASSIFIER + obf.score * WEIGHT_OBFUSCATION, 3
    )

    # ── 위험 레벨 구간 ──────────────────────────────────────────────────────
    # SAFE     : score < 0.50  → Claude API SKIP (TOKEN_SAVE)
    # MEDIUM   : 0.50 ≤ score < 0.75
    # HIGH     : 0.75 ≤ score < 0.90
    # CRITICAL : score ≥ 0.90
    if final_score >= RISK_THRESHOLD_CRITICAL:
        level = "critical"
    elif final_score >= RISK_THRESHOLD_HIGH:
        level = "high"
    elif final_score >= RISK_THRESHOLD_LLM:
        level = "medium"
    else:
        level = "safe"

    evidence: list[str] = []
    if clf.patterns_found:
        evidence.append(f"탐지 패턴: {', '.join(clf.patterns_found)}")
    if obf.techniques:
        evidence.append(f"난독화 기법: {', '.join(obf.techniques)}")
    if clf.brief_reason:
        evidence.append(f"분류 근거: {clf.brief_reason}")
    evidence.append(
        f"엔트로피: {obf.entropy:.2f} | "
        f"패턴 점수: {clf.confidence:.2f} | "
        f"난독화 점수: {obf.score:.2f}"
    )

    llm_required = final_score >= RISK_THRESHOLD_LLM
    if not llm_required:
        # TOKEN_SAVE: 로컬 모델 점수가 낮으면 여기서 분기 — LLM 비용 제로
        logger.info(
            f"[risk_scorer] score={final_score:.3f} < {RISK_THRESHOLD_LLM} → LLM SKIP (토큰 절감)"
        )

    return LocalModelResult(
        risk_score=final_score,
        risk_level=level,
        llm_required=llm_required,
        pattern_labels=clf.patterns_found,
        obfuscation_techniques=obf.techniques,
        evidence=evidence,
        classifier_result=clf,
        obfuscation_result=obf,
    )
