#!/usr/bin/env python3
"""
시나리오 API 연결 진단 스크립트
실행: cd backend && python test_scenario_api.py
"""
import os, sys

# .env 먼저 로드
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

print("=" * 60)
print("  MalScript — 시나리오 API 진단")
print("=" * 60)

# ── 1. API 키 확인 ─────────────────────────────────────────
api_key = os.getenv("ANTHROPIC_API_KEY", "")
print(f"\n[1] ANTHROPIC_API_KEY")
if not api_key:
    print("    ✗ 없음 — .env 파일에 ANTHROPIC_API_KEY가 설정돼 있는지 확인하세요.")
    sys.exit(1)
print(f"    ✓ 설정됨  길이={len(api_key)}  앞={api_key[:20]}...")

# ── 2. 패키지 임포트 확인 ──────────────────────────────────
print(f"\n[2] 패키지 임포트")
try:
    import anthropic
    print(f"    ✓ anthropic {anthropic.__version__}")
except ImportError as e:
    print(f"    ✗ anthropic 없음: {e}")
    sys.exit(1)

try:
    import httpx
    print(f"    ✓ httpx {httpx.__version__}")
except ImportError as e:
    print(f"    ✗ httpx 없음: {e}")
    sys.exit(1)

# ── 3. httpx 클라이언트 초기화 ────────────────────────────
print(f"\n[3] httpx 클라이언트 초기화")
_http = None
try:
    _http = httpx.Client(timeout=30.0)
    client = anthropic.Anthropic(api_key=api_key, http_client=_http)
    print("    ✓ 기본 클라이언트 생성 OK")
except Exception as e:
    print(f"    ✗ 기본 클라이언트 실패: {type(e).__name__}: {e}")
    print("      → trust_env=False 로 재시도 (프록시 우회)...")
    try:
        _http = httpx.Client(trust_env=False, timeout=30.0)
        client = anthropic.Anthropic(api_key=api_key, http_client=_http)
        print("    ✓ trust_env=False 클라이언트 생성 OK")
    except Exception as e2:
        print(f"    ✗ 재시도도 실패: {type(e2).__name__}: {e2}")
        sys.exit(1)

# ── 4. 네트워크 연결 (ping) ───────────────────────────────
print(f"\n[4] Claude API 네트워크 연결 테스트")
try:
    resp = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=8,
        messages=[{"role": "user", "content": "ping"}],
    )
    print(f"    ✓ 연결 성공  응답={resp.content[0].text!r}")
    print(f"      토큰 사용: 입력={resp.usage.input_tokens} 출력={resp.usage.output_tokens}")
except anthropic.AuthenticationError as e:
    print(f"    ✗ 인증 실패 — API 키가 올바른지 확인하세요: {e}")
    sys.exit(1)
except anthropic.PermissionDeniedError as e:
    print(f"    ✗ 권한 없음: {e}")
    sys.exit(1)
except Exception as e:
    print(f"    ✗ 연결 실패: {type(e).__name__}: {e}")
    sys.exit(1)

# ── 5. 시나리오 프롬프트 확인 ─────────────────────────────
print(f"\n[5] 시나리오 프롬프트 모듈")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    from scenario.scenario_prompts import SCENARIO_SYSTEM_PROMPT, build_scenario_prompt
    print(f"    ✓ 로드 OK  길이={len(SCENARIO_SYSTEM_PROMPT)}")
    print(f"      한국어 포함: {'한국어' in SCENARIO_SYSTEM_PROMPT}")
except Exception as e:
    print(f"    ✗ 로드 실패: {e}")
    sys.exit(1)

# ── 6. 실제 시나리오 생성 테스트 ──────────────────────────
print(f"\n[6] 실제 시나리오 생성 (claude-sonnet-4-6)")
user_prompt = build_scenario_prompt(
    "Target platform: Windows\n"
    "Risk score: 0.82 (HIGH)\n"
    "Language: bat | File: ransomware_test.bat\n"
    "Detected patterns: 파일 암호화, C2 통신, 권한 상승"
)
try:
    resp = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=SCENARIO_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )
    raw = resp.content[0].text.strip()
    tokens = resp.usage.input_tokens + resp.usage.output_tokens
    print(f"    ✓ 응답 수신  토큰={tokens}  길이={len(raw)}")
    print(f"\n    응답 앞 400자:")
    print("    " + raw[:400].replace("\n", "\n    "))
except anthropic.BadRequestError as e:
    print(f"    ✗ 요청 오류: {e}")
except anthropic.APIStatusError as e:
    print(f"    ✗ API 상태 오류 {e.status_code}: {e.message}")
except Exception as e:
    print(f"    ✗ 실패: {type(e).__name__}: {e}")
    sys.exit(1)

print()
print("=" * 60)
print("  진단 완료 — 모든 단계 정상")
print("=" * 60)
