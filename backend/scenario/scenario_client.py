# backend/scenario/scenario_client.py
from __future__ import annotations
import json, logging, os, re, sys, uuid
from security.schemas import AttackScenario, ScenarioStep, DockerConfig
from .scenario_prompts import SCENARIO_SYSTEM_PROMPT, build_scenario_prompt, build_analysis_summary

import atexit
import httpx as _httpx_mod

logger = logging.getLogger(__name__)
MODEL      = 'claude-sonnet-4-6'
MAX_TOKENS = 4096

# 모듈 레벨 httpx 싱글톤 — 매 호출마다 새 Client 생성 시 소켓 누수
_http_client: _httpx_mod.Client | None = None

def _get_http_client() -> _httpx_mod.Client:
    global _http_client
    if _http_client is None or _http_client.is_closed:
        try:
            _http_client = _httpx_mod.Client(timeout=60.0)
        except Exception:
            _http_client = _httpx_mod.Client(trust_env=False, timeout=60.0)
        atexit.register(_http_client.close)
    return _http_client


def _safe_print(msg: str) -> None:
    """Windows cp949 콘솔에서도 안전하게 출력 (인코딩 불가 문자는 ? 대체)."""
    try:
        print(msg, flush=True)
    except UnicodeEncodeError:
        enc  = sys.stdout.encoding or 'utf-8'
        safe = msg.encode(enc, errors='replace').decode(enc, errors='replace')
        print(safe, flush=True)


def generate_scenario(analysis_result) -> AttackScenario:
    api_key = os.getenv('ANTHROPIC_API_KEY')
    if not api_key:
        logger.warning('[scenario_client] ANTHROPIC_API_KEY not set -> fallback')
        return _fallback_scenario(analysis_result)

    # 로그 파일에 쓸 값을 미리 준비
    summary     = build_analysis_summary(analysis_result)
    user_prompt = build_scenario_prompt(summary)

    try:
        import anthropic
        from api_log import save as api_save

        # 모듈 레벨 싱글톤 사용 — 매번 새 연결 생성 방지
        client = anthropic.Anthropic(api_key=api_key, http_client=_get_http_client())

        logger.info('[scenario_client] call | model=%s prompt_len=%d', MODEL, len(user_prompt))
        _safe_print(f'[scenario_client] Claude API call | model={MODEL}')

        try:
            response = client.messages.create(
                model=MODEL, max_tokens=MAX_TOKENS,
                system=SCENARIO_SYSTEM_PROMPT,
                messages=[{'role': 'user', 'content': user_prompt}],
            )
            raw       = response.content[0].text.strip()
            tokens_in = response.usage.input_tokens
            tokens_out= response.usage.output_tokens
            logger.info('[scenario_client] done | tokens=%d raw_len=%d', tokens_in + tokens_out, len(raw))
            _safe_print(f'[scenario_client] API response | tokens={tokens_in + tokens_out} raw_len={len(raw)}')

            scenario  = _parse_scenario(raw, analysis_result)
            parse_ok  = '폴백' not in scenario.description

            # ── 로그 저장 ──
            api_save(
                call_type    = 'scenario',
                model        = MODEL,
                system_prompt= SCENARIO_SYSTEM_PROMPT,
                user_prompt  = user_prompt,
                raw_response = raw,
                tokens_in    = tokens_in,
                tokens_out   = tokens_out,
                success      = True,
                parse_ok     = parse_ok,
                extra        = {
                    'filename': analysis_result.filename,
                    'risk_level': str(analysis_result.local.risk_level),
                    'scenario_title': scenario.title,
                },
            )

            scenario.token_usage = tokens_in + tokens_out
            return scenario

        except Exception as api_err:
            # API 호출 자체 실패
            api_save(
                call_type    = 'scenario',
                model        = MODEL,
                system_prompt= SCENARIO_SYSTEM_PROMPT,
                user_prompt  = user_prompt,
                raw_response = None,
                success      = False,
                error        = f'{type(api_err).__name__}: {api_err}',
                extra        = {'filename': analysis_result.filename},
            )
            raise   # 외부 except 로 전파

    except Exception as e:
        logger.error('[scenario_client] error: %s: %s', type(e).__name__, e, exc_info=True)
        _safe_print(f'[scenario_client] EXCEPTION: {type(e).__name__}: {e}')
        return _fallback_scenario(analysis_result)


# ── JSON 추출 / 정제 헬퍼 ────────────────────────────────────────────────────

def _clean_json(s: str) -> str:
    """Claude가 자주 삽입하는 비표준 JSON 요소를 제거한다."""
    s = s.replace('“', '"').replace('”', '"')   # 스마트 따옴표
    s = s.replace('‘', "'").replace('’', "'")
    s = re.sub(r',\s*([}\]])', r'\1', s)     # trailing commas
    s = re.sub(r'//[^\n]*', '', s)            # // comments
    s = re.sub(r'/\*[\s\S]*?\*/', '', s)      # /* comments */
    return s.strip()


def _extract_balanced_json(raw: str):
    """최초의 { 에서 시작해 괄호 균형이 맞는 지점까지 추출한다."""
    start = raw.find('{')
    if start == -1:
        return None
    depth, in_str, escape = 0, False, False
    for i, ch in enumerate(raw[start:], start):
        if escape:
            escape = False; continue
        if ch == '\\' and in_str:
            escape = True;  continue
        if ch == '"':
            in_str = not in_str; continue
        if in_str:
            continue
        if ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return raw[start:i + 1]
    return None


def _parse_scenario(raw: str, analysis_result) -> AttackScenario:
    _safe_print(f'[scenario_client] raw[:300]: {repr(raw[:300])}')

    md_stripped = re.sub(r'```(?:json)?\s*|\s*```', '', raw).strip()
    balanced    = _extract_balanced_json(raw) or ''
    balanced_md = _extract_balanced_json(md_stripped) or ''

    candidates = []
    for s in [raw, md_stripped, balanced, balanced_md]:
        if s:
            candidates.append(s)
            cleaned = _clean_json(s)
            if cleaned != s:
                candidates.append(cleaned)

    seen: set = set()
    for idx, candidate in enumerate(candidates):
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            d = json.loads(candidate)
            result = _dict_to_scenario(d)
            _safe_print(f'[scenario_client] JSON parse OK (candidate #{idx + 1})')
            return result
        except json.JSONDecodeError as e:
            logger.warning('[scenario_client] JSONDecodeError #%d: %s', idx + 1, e)
        except Exception as e:
            logger.warning('[scenario_client] dict->scenario error #%d: %s: %s',
                           idx + 1, type(e).__name__, e)

    _safe_print(f'[scenario_client] PARSE FAIL -- all {len(seen)} candidates exhausted')
    logger.warning('[scenario_client] JSON parse failed. raw[:300]=%r', raw[:300])
    return _fallback_scenario(analysis_result)


def _dict_to_scenario(d: dict) -> AttackScenario:
    raw_steps = d.get('steps') or []
    steps = []
    for i, s in enumerate(raw_steps if isinstance(raw_steps, list) else []):
        if not isinstance(s, dict):
            continue
        steps.append(ScenarioStep(
            step_number   = int(s.get('step_number', i + 1)),
            title         = str(s.get('title', '')),
            description   = str(s.get('description', '')),
            command       = str(s.get('command', '')),
            exec_command  = str(s.get('exec_command', '')),
            mitre_technique = str(s.get('mitre_technique', '')),
            expected_outcome = str(s.get('expected_outcome', '')),
        ))

    dc = d.get('docker_config') or {}
    if not isinstance(dc, dict):
        dc = {}
    ports = dc.get('target_ports', [8080])
    docker_cfg = DockerConfig(
        attacker_image = str(dc.get('attacker_image', 'kalilinux/kali-rolling')),
        target_image   = str(dc.get('target_image',   'webgoat/goat-and-wolf')),
        target_ports   = [int(p) for p in ports] if isinstance(ports, list) else [8080],
        env_vars       = dc.get('env_vars', {}) if isinstance(dc.get('env_vars'), dict) else {},
        preset_name    = str(dc.get('preset_name', '')),
    )

    raw_defenses = d.get('defenses') or []
    defenses = [str(x) for x in raw_defenses] if isinstance(raw_defenses, list) else []

    return AttackScenario(
        scenario_id = str(uuid.uuid4())[:8],
        title       = str(d.get('title',       'Unnamed Scenario')),
        description = str(d.get('description', '')),
        difficulty  = str(d.get('difficulty',  'MEDIUM')),
        steps       = steps,
        defenses    = defenses,
        docker_config = docker_cfg,
    )


def _fallback_scenario(result) -> AttackScenario:
    name  = result.filename if result else 'unknown'
    level = result.local.risk_level.upper() if result else 'MEDIUM'
    return AttackScenario(
        scenario_id = str(uuid.uuid4())[:8],
        title       = f'시나리오: {name}',
        description = f'자동 생성 폴백 시나리오 (API 미연결). 위험도: {level}',
        difficulty  = level,
        steps=[
            ScenarioStep(step_number=1, title='초기 침투',
                         description='피싱 이메일을 통해 악성 스크립트 전달.',
                         command='', exec_command='', mitre_technique='T1566',
                         expected_outcome='피해자 호스트에서 스크립트 실행됨.'),
            ScenarioStep(step_number=2, title='실행 및 지속성',
                         description='스크립트 실행 후 지속성 확보.',
                         command='', exec_command='', mitre_technique='T1059',
                         expected_outcome='지속적인 원격 접근 확보.'),
        ],
        defenses=[
            'PowerShell 스크립트 블록 로깅 및 AMSI 활성화.',
            '신뢰되지 않은 도메인으로의 아웃바운드 연결 차단.',
            '엔드포인트 행위 기반 탐지 솔루션 배포.',
        ],
    )
