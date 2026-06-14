# backend/scenario/scenario_prompts.py
# Prompt templates for attack scenario generation via Claude API
from __future__ import annotations

SCENARIO_SYSTEM_PROMPT = '''\
당신은 사이버 보안 레드팀 전문가로, 악성 스크립트 분석 결과를 바탕으로
Docker 가상 환경(Kali Linux 공격자 컨테이너 + Linux 타깃 컨테이너)에서 실행 가능한
단계별 공격 시나리오를 생성합니다.

[한국어 출력 규칙 — 필수]
아래 필드는 반드시 자연스러운 한국어로 작성하십시오:
  - title          : 시나리오 제목 (짧고 명확하게)
  - description    : 시나리오 요약 (2~3문장)
  - steps[].title       : 각 단계 제목
  - steps[].description : 단계 상세 설명 (공격자 행동 및 목적)
  - steps[].expected_outcome : 예상 결과 (공격자가 달성하는 것)
  - defenses[]     : 방어 대책 (구체적인 한국어 문장)

아래 필드는 영문/기술 형식 그대로 유지하십시오:
  - command, exec_command, mitre_technique, difficulty, docker_config 내 모든 필드

[플랫폼 규칙 — 필수]
- "command": 악성코드 원본 명령어 (표시용)
- "exec_command": Kali Linux Docker 컨테이너에서 실제 실행할 Linux/bash 동등 명령어.
  변환 규칙:
    * cmd.exe /c "..."       -> bash -c "..."
    * powershell.exe -...    -> curl, python3, nc 등 bash 동등 명령
    * IF EXIST / IF /I ...   -> bash if [ ... ] 스타일 또는 빈 문자열
    * fltmc, schtasks, reg   -> lsmod, cron 등 Linux 동등 또는 빈 문자열
    * Base64 인코딩 PS       -> echo '<b64>' | base64 -d
    * C2 다운로드(IEX/wget)  -> curl http://... 또는 wget http://...
    * 환경 변수 조작         -> export VAR=value; bash -c "..."
    * UAC / 권한 확인        -> id; sudo -l
    * Windows Defender 비활성화 -> exec_command를 ""로 설정
  Linux 동등 명령이 없으면 exec_command를 ""로 설정 (시뮬레이션에서 건너뜀).

[출력 규칙]
- 아래 스키마에 맞는 유효한 JSON만 반환. 마크다운 불가, 추가 텍스트 불가.
- steps: 3~6개의 구체적인 단계.
- difficulty: LOW / MEDIUM / HIGH / CRITICAL 중 하나
- defenses: 2~4개의 구체적인 방어 대책

[JSON 스키마]
{
  "title": "한국어 시나리오 제목",
  "description": "한국어로 2~3문장 시나리오 요약",
  "difficulty": "MEDIUM",
  "steps": [
    {
      "step_number": 1,
      "title": "한국어 단계 제목",
      "description": "한국어로 단계 상세 설명",
      "command": "원본 명령어 (표시용, 영문 유지)",
      "exec_command": "Kali Docker용 Linux/bash 명령어 (없으면 빈 문자열)",
      "mitre_technique": "T1059.001",
      "expected_outcome": "한국어로 공격자가 달성하는 예상 결과"
    }
  ],
  "defenses": ["한국어 방어 대책 1", "한국어 방어 대책 2"],
  "docker_config": {
    "attacker_image": "kalilinux/kali-rolling",
    "target_image": "webgoat/goat-and-wolf",
    "target_ports": [8080],
    "env_vars": {},
    "preset_name": "webgoat-basic"
  }
}
'''


def build_scenario_prompt(analysis_summary: str) -> str:
    return f'''[분석 결과]
{analysis_summary}

위 위협 프로파일에 대한 공격 시나리오 JSON을 생성하세요.
제목, 설명, 단계 제목/설명, 예상 결과, 방어 대책은 반드시 한국어로 작성하고,
명령어(command/exec_command)와 기술 필드는 영문/기술 형식을 유지하세요.
exec_command에는 모든 단계에 가능한 Linux/Kali 동등 명령어를 채워주세요.'''


_WINDOWS_EXTS = {".bat", ".ps1", ".vbs", ".cmd", ".wsf", ".hta"}
_LINUX_EXTS   = {".sh", ".bash", ".zsh", ".py", ".rb", ".pl"}


def build_analysis_summary(result) -> str:
    """Build a compact text summary from AnalysisResult for the scenario prompt."""
    ext = ("." + result.filename.rsplit(".", 1)[-1].lower()) if "." in result.filename else ""
    if ext in _WINDOWS_EXTS:
        platform = "Windows"
    elif ext in _LINUX_EXTS:
        platform = "Linux"
    else:
        platform = "Unknown"

    lines = [
        f"Target platform: {platform}",
        f"Risk score: {result.local.risk_score:.2f} ({result.local.risk_level.upper()})",
        f"Language: {result.lang_hint} | File: {result.filename}",
    ]
    if result.local.pattern_labels:
        lines.append(f"Detected patterns: {', '.join(result.local.pattern_labels)}")
    if result.local.obfuscation_techniques:
        lines.append(f"Obfuscation: {', '.join(result.local.obfuscation_techniques)}")
    if result.llm and result.llm.mitre_techniques:
        techs = ', '.join(f"{t.technique_id}({t.tactic})" for t in result.llm.mitre_techniques)
        lines.append(f"ATT&CK techniques: {techs}")
    if result.llm and result.llm.attack_chain:
        lines.append("Attack chain:")
        lines.extend(f"  {s}" for s in result.llm.attack_chain)
    if result.vulnerabilities and result.vulnerabilities.vulnerabilities:
        cwe_list = ', '.join(v.cwe_id for v in result.vulnerabilities.vulnerabilities)
        lines.append(f"CWE vulnerabilities: {cwe_list}")
        lines.append(f"Highest severity: {result.vulnerabilities.highest_severity}")
    return '\n'.join(lines)
