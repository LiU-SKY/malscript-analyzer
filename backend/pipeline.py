# backend/pipeline.py
# TOKEN_SAVE strategy:
#   - API key SET   : threshold=0.10 (any pattern triggers Claude)
#   - API key ABSENT: threshold=0.50 (local-only, zero API cost)
from __future__ import annotations
import os
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
import time, logging
from preprocessor import preprocess, compress_for_llm
from local_model.risk_scorer import ensemble_score
from security.schemas import AnalysisResult, LocalModelOutput, LLMReport, RiskLevel, VulnerabilityReport
from vulnerability.vuln_mapper import map_techniques_to_vulns, map_patterns_to_vulns

logger = logging.getLogger(__name__)

# API key 유무에 따라 LLM 호출 임계값 분기
# - 키 있음: 0.10 -> 패턴 하나라도 잡히면 Claude 호출
# - 키 없음: 0.50 -> Ollama 점수가 높아야 호출 (TOKEN_SAVE)
_API_KEY = os.getenv('ANTHROPIC_API_KEY', '')
RISK_THRESHOLD_LLM = 0.10 if _API_KEY else 0.50

try:
    from llm_client.claude_client import call_claude
    LLM_AVAILABLE = True
except ImportError:
    LLM_AVAILABLE = False


def run_pipeline(filename: str, raw_bytes: bytes) -> AnalysisResult:
    t_start = time.perf_counter()

    prep = preprocess(raw_bytes, filename)
    logger.info(f'[pipeline] preprocessed | lang={prep.lang_hint} lines={prep.line_count}')

    local = ensemble_score(prep.cleaned_code, prep.lang_hint)
    logger.info(f'[pipeline] local score={local.risk_score:.3f} level={local.risk_level}')

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

    # LLM 호출 여부 결정
    # API 키 있을 때: 의심 패턴 하나라도 검출되면 즉시 Claude 호출
    # API 키 없을 때: 앙상블 점수 >= 0.50 일 때만 (Ollama 필요)
    llm_needed = (local.risk_score >= RISK_THRESHOLD_LLM) or bool(local.pattern_labels)
    llm_report: LLMReport | None = None
    llm_skipped = not llm_needed

    if llm_needed and LLM_AVAILABLE and _API_KEY:
        logger.info(
            f'[pipeline] calling Claude API | score={local.risk_score:.3f} '
            f'patterns={local.pattern_labels} threshold={RISK_THRESHOLD_LLM}'
        )
        compressed = compress_for_llm(prep.cleaned_code, local.evidence)
        llm_report = call_claude(compressed, local_output)
    elif llm_needed and not _API_KEY:
        logger.info(f'[pipeline] TOKEN_SAVE: no API key -> Claude skipped')
        llm_skipped = True
    else:
        logger.info(f'[pipeline] no suspicious patterns detected -> Claude skipped')

    # 취약점 매핑
    vuln_report: VulnerabilityReport | None = None
    if llm_report and llm_report.mitre_techniques:
        ids = [t.technique_id for t in llm_report.mitre_techniques]
        vuln_report = map_techniques_to_vulns(ids)
        logger.info(f'[pipeline] vuln mapping: {len(vuln_report.vulnerabilities)} items (ATT&CK)')
    elif local.pattern_labels:
        vuln_report = map_patterns_to_vulns(local.pattern_labels)
        logger.info(f'[pipeline] vuln mapping: {len(vuln_report.vulnerabilities)} items (patterns)')

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
        vulnerabilities=vuln_report,
    )


def _to_risk_level(score: float) -> RiskLevel:
    if score >= 0.90: return RiskLevel.CRITICAL
    if score >= 0.75: return RiskLevel.HIGH
    if score >= 0.50: return RiskLevel.MEDIUM
    return RiskLevel.SAFE
