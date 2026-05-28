# backend/local_model/obfuscation.py
from __future__ import annotations
import re
import math
import base64
from dataclasses import dataclass, field


@dataclass
class ObfuscationResult:
    score: float
    techniques: list[str] = field(default_factory=list)
    entropy: float = 0.0
    details: dict = field(default_factory=dict)


RE_BASE64     = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
RE_EVAL_CHAIN = re.compile(r'(eval|exec|iex|invoke-expression)\s*[\(\[]', re.IGNORECASE)
RE_UNICODE    = re.compile(r'\\u[0-9a-fA-F]{4}')
RE_HEX        = re.compile(r'(\\x[0-9a-fA-F]{2}){10,}')
RE_LONG_LINE  = re.compile(r'^.{1000,}$', re.MULTILINE)
RE_CHAR_SPAM  = re.compile(r'\bchr?\s*\(', re.IGNORECASE)
RE_CHARCODE   = re.compile(r'fromCharCode\s*\(', re.IGNORECASE)
RE_OBFVAR     = re.compile(r'\b[a-z0-9]{20,}\b')


def detect(code: str) -> ObfuscationResult:
    techniques: list[str] = []
    details: dict = {}
    total_score = 0.0

    entropy = _shannon_entropy(code)
    details["entropy"] = round(entropy, 3)
    if entropy > 5.5:
        techniques.append("고엔트로피 코드 (난독화 의심)")
        total_score += 0.30
    elif entropy > 5.0:
        total_score += 0.10

    b64_matches = RE_BASE64.findall(code)
    details["base64_count"] = len(b64_matches)
    if b64_matches:
        valid_b64 = _count_valid_base64(b64_matches)
        details["valid_base64_count"] = valid_b64
        if valid_b64 >= 1:
            techniques.append(f"Base64 인코딩 문자열 {valid_b64}개 탐지")
            total_score += min(0.20 * valid_b64, 0.35)

    eval_count = len(RE_EVAL_CHAIN.findall(code))
    details["eval_chain_count"] = eval_count
    if eval_count >= 2:
        techniques.append(f"eval/exec 중첩 체인 ({eval_count}회)")
        total_score += 0.25
    elif eval_count == 1:
        total_score += 0.10

    uni_count = len(RE_UNICODE.findall(code))
    details["unicode_escape_count"] = uni_count
    if uni_count > 10:
        techniques.append(f"유니코드 이스케이프 남용 ({uni_count}개)")
        total_score += 0.20

    hex_count = len(RE_HEX.findall(code))
    details["hex_escape_blocks"] = hex_count
    if hex_count >= 1:
        techniques.append(f"16진수 바이트 시퀀스 ({hex_count}블록)")
        total_score += 0.20

    long_lines = RE_LONG_LINE.findall(code)
    details["long_line_count"] = len(long_lines)
    if long_lines:
        techniques.append(f"초장문 라인 {len(long_lines)}개 (인코딩 페이로드 의심)")
        total_score += 0.15

    char_count = len(RE_CHAR_SPAM.findall(code))
    charcode_count = len(RE_CHARCODE.findall(code))
    details["char_call_count"] = char_count + charcode_count
    if char_count + charcode_count > 10:
        techniques.append(f"문자코드 변환 남용 ({char_count + charcode_count}회)")
        total_score += 0.15

    obfvar_count = len(RE_OBFVAR.findall(code))
    details["obfuscated_var_count"] = obfvar_count
    if obfvar_count > 5:
        techniques.append(f"난독화된 변수명 패턴 ({obfvar_count}개)")
        total_score += 0.10

    return ObfuscationResult(
        score=round(min(total_score, 1.0), 3),
        techniques=techniques,
        entropy=entropy,
        details=details,
    )


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    total = len(text)
    return -sum((c / total) * math.log2(c / total) for c in freq.values())


def _count_valid_base64(candidates: list[str]) -> int:
    valid = 0
    for s in candidates:
        try:
            decoded = base64.b64decode(s + "==")
            if len(decoded) > 20:
                valid += 1
        except Exception:
            pass
    return valid
