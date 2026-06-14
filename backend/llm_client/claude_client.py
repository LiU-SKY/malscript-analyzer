# backend/llm_client/claude_client.py
from __future__ import annotations
import json, logging, os, re
import anthropic
from .prompts import SYSTEM_PROMPT, build_user_prompt, build_local_summary
from security.schemas import LLMReport, MitreTechnique
from security.attack_mapper import enrich_mitre_techniques

import atexit
import httpx as _httpx

logger = logging.getLogger(__name__)
MODEL      = 'claude-sonnet-4-6'
MAX_TOKENS = 2048

# 모듈 레벨 httpx 싱글톤 — 매 호출마다 생성하면 소켓/FD 누수
_http_client: _httpx.Client | None = None

def _get_http_client() -> _httpx.Client:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        _http_client = _httpx.Client(trust_env=False, timeout=60.0)
        atexit.register(_http_client.close)
    return _http_client


def call_claude(compressed_code: str, local) -> LLMReport:
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        logger.warning('[claude_client] ANTHROPIC_API_KEY not set -> falling back to local results')
        return _fallback_report(local)

    client = anthropic.Anthropic(api_key=api_key, http_client=_get_http_client())

    local_summary = build_local_summary(local)
    user_prompt   = build_user_prompt(compressed_code, local_summary)
    logger.info('[claude_client] call | model=%s prompt_len=%d', MODEL, len(user_prompt))

    try:
        from api_log import save as api_save

        try:
            response = client.messages.create(
                model=MODEL,
                max_tokens=MAX_TOKENS,
                system=SYSTEM_PROMPT,
                messages=[{'role': 'user', 'content': user_prompt}],
            )
            raw_text   = response.content[0].text.strip()
            tokens_in  = response.usage.input_tokens
            tokens_out = response.usage.output_tokens
            token_used = tokens_in + tokens_out
            logger.info('[claude_client] done | tokens=%d raw_len=%d', token_used, len(raw_text))

            parsed   = _parse_response(raw_text, local)
            parse_ok = bool(parsed.attack_chain or parsed.mitre_techniques)

            api_save(
                call_type    = 'llm_analysis',
                model        = MODEL,
                system_prompt= SYSTEM_PROMPT,
                user_prompt  = user_prompt,
                raw_response = raw_text,
                tokens_in    = tokens_in,
                tokens_out   = tokens_out,
                success      = True,
                parse_ok     = parse_ok,
            )

            parsed.token_usage = token_used
            parsed.mitre_techniques = enrich_mitre_techniques(parsed.mitre_techniques)
            return parsed

        except anthropic.APIError as e:
            api_save(
                call_type    = 'llm_analysis',
                model        = MODEL,
                system_prompt= SYSTEM_PROMPT,
                user_prompt  = user_prompt,
                raw_response = None,
                success      = False,
                error        = f'APIError: {e}',
            )
            logger.error('[claude_client] API error: %s', e)
            return _fallback_report(local)

    except Exception as e:
        logger.error('[claude_client] unexpected error: %s', e, exc_info=True)
        return _fallback_report(local)


def _parse_response(raw: str, local) -> LLMReport:
    candidates = [
        raw,
        re.sub(r'```(?:json)?\s*|\s*```', '', raw).strip(),
    ]
    m = re.search(r'\{[\s\S]*\}', raw)
    if m:
        candidates.append(m.group())

    for candidate in candidates:
        try:
            data = json.loads(candidate)
            return _to_report(data)
        except json.JSONDecodeError:
            continue
        except Exception as e:
            logger.warning('[claude_client] _to_report conversion error: %s: %s', type(e).__name__, e)
            continue

    logger.warning('[claude_client] JSON parse failed (all candidates exhausted). raw[:300]=%r', raw[:300])
    return _fallback_report(local)


def _to_report(data: dict) -> LLMReport:
    raw_chain    = data.get('attack_chain') or []
    attack_chain = [str(s) for s in raw_chain] if isinstance(raw_chain, list) else []

    raw_techs  = data.get('mitre_techniques') or []
    techniques = []
    for t in raw_techs:
        if not isinstance(t, dict):
            continue
        techniques.append(MitreTechnique(
            technique_id = str(t.get('technique_id', '')),
            name         = str(t.get('name', '')),
            tactic       = str(t.get('tactic', '')),
            url          = str(t.get('url', '')),
        ))

    return LLMReport(
        attack_chain     = attack_chain,
        mitre_techniques = techniques,
        recommendation   = str(data.get('recommendation') or ''),
        summary          = str(data.get('summary') or ''),
    )


def _fallback_report(local) -> LLMReport:
    patterns = ', '.join(local.pattern_labels) if local.pattern_labels else '패턴 없음'
    return LLMReport(
        attack_chain=[
            f'1단계: 의심 스크립트 실행 시도 (위험도 {local.risk_score:.2f})',
            f'2단계: {patterns} 탐지됨',
            '3단계: 추가 페이로드 실행 또는 시스템 접근 시도 가능',
        ],
        mitre_techniques=[],
        recommendation=(
            '해당 스크립트의 실행을 즉시 차단하고 격리된 환경에서만 분석하세요. '
            '스크립트 출처를 확인하고 관련 시스템 로그를 점검하세요.'
        ),
        summary=(
            f'위험도 {local.risk_score:.2f}의 의심 스크립트 탐지. '
            f'로컬 분석 결과: {patterns}.'
        ),
        token_usage=0,
    )
