# backend/llm_client/prompts.py
# TOKEN_SAVE: 시스템 프롬프트 고정 캐시 + 압축본만 유저 프롬프트에 삽입

SYSTEM_PROMPT = """\
당신은 악성 스크립트 분석 전문 보안 연구원입니다.
로컬 AI 모델이 1차 분류한 결과와 의심 코드 발췌를 바탕으로
공격 기법을 분석하고 MITRE ATT&CK 프레임워크에 매핑합니다.

[출력 규칙]
- 반드시 아래 JSON 형식만 반환하세요. 마크다운 코드블록, 설명 문자열 불필요.
- attack_chain: 공격 단계를 순서대로 2~5개 항목으로 서술 (한국어)
- mitre_techniques: 탐지된 기법만 포함, 불확실하면 빈 배열
- recommendation: 구체적인 대응 방안을 2~4문장으로 (한국어)
- summary: 전체 분석 결과를 1~2문장으로 요약 (한국어)

[JSON 형식]
{
  "attack_chain": ["1단계: ...", "2단계: ..."],
  "mitre_techniques": [
    {"technique_id": "T1059.001", "name": "PowerShell", "tactic": "Execution"}
  ],
  "recommendation": "...",
  "summary": "..."
}"""


def build_user_prompt(compressed_code: str, local_summary: str) -> str:
    """TOKEN_SAVE: 원본 전체 코드 대신 압축본 + 로컬 분석 결과만 전달"""
    return f"""\
[로컬 AI 1차 분석 결과]
{local_summary}

[의심 코드 발췌 (전처리 압축본)]
{compressed_code}

위 정보를 바탕으로 JSON 리포트를 생성하세요."""


def build_local_summary(local) -> str:
    lines = [
        f"위험도 점수: {local.risk_score:.2f} ({local.risk_level.upper()})",
        f"엔트로피: {local.entropy:.2f}",
    ]
    if local.pattern_labels:
        lines.append(f"탐지 패턴: {', '.join(local.pattern_labels)}")
    if local.obfuscation_techniques:
        lines.append(f"난독화 기법: {', '.join(local.obfuscation_techniques)}")
    if local.evidence:
        lines.append("근거:")
        lines.extend(f"  - {e}" for e in local.evidence[:5])
    return "\n".join(lines)
