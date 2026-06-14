# backend/local_model/classifier.py
from __future__ import annotations
import json
import re
import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

OLLAMA_MODEL = "mistral"

PATTERN_CATALOG = [
    "PowerShell 다운로더",
    "원격 셸 / 리버스 셸",
    "프로세스 인젝션",
    "자격증명 탈취",
    "지속성 설치",
    "C2 통신",
    "파일 암호화",
    "권한 상승",
    "난독화 실행",
    "정찰 / 시스템 열거",
]

CLASSIFY_PROMPT = """You are a malware analyst. Analyze the following script and identify which malicious patterns it contains.

Script language: {lang}
Script content:
```
{code}
```

Return ONLY valid JSON in this exact format, no other text:
{{
  "patterns_found": ["pattern1", "pattern2"],
  "confidence": 0.85,
  "brief_reason": "One sentence explaining why."
}}

Available patterns to choose from:
{catalog}

If the script looks benign, return an empty list for patterns_found and low confidence (0.0-0.3).
"""


@dataclass
class ClassifierResult:
    patterns_found: list[str] = field(default_factory=list)
    confidence: float = 0.0
    brief_reason: str = ""
    raw_response: str = ""
    error: str | None = None


OLLAMA_TIMEOUT_S = 30   # Ollama가 응답 없으면 30초 후 폴백


def classify(code: str, lang_hint: str = "Unknown") -> ClassifierResult:
    catalog_str = "\n".join(f"- {p}" for p in PATTERN_CATALOG)
    prompt = CLASSIFY_PROMPT.format(
        lang=lang_hint,
        code=code[:3_000],
        catalog=catalog_str,
    )
    try:
        import ollama  # lazy import — proxy 환경에서 모듈 로딩 시 crash 방지
        import concurrent.futures as _cf

        def _call_ollama():
            return ollama.generate(
                model=OLLAMA_MODEL,
                prompt=prompt,
                options={"temperature": 0.1, "num_predict": 300},
            )

        with _cf.ThreadPoolExecutor(max_workers=1) as ex:
            try:
                response = ex.submit(_call_ollama).result(timeout=OLLAMA_TIMEOUT_S)
            except _cf.TimeoutError:
                logger.warning(f"[classifier] Ollama timeout after {OLLAMA_TIMEOUT_S}s -> falling back to rule-based")
                return _rule_based_fallback(code)

        raw = response["response"].strip()
        return _parse_response(raw)
    except Exception as e:
        logger.warning(f"[classifier] Ollama call failed: {e} -> using rule-based fallback")
        return _rule_based_fallback(code)


def _parse_response(raw: str) -> ClassifierResult:
    cleaned = re.sub(r"```(?:json)?|```", "", raw).strip()
    try:
        data = json.loads(cleaned)
        return ClassifierResult(
            patterns_found=data.get("patterns_found", []),
            confidence=float(data.get("confidence", 0.0)),
            brief_reason=data.get("brief_reason", ""),
            raw_response=raw,
        )
    except json.JSONDecodeError:
        logger.warning(f"[classifier] JSON parse failed: {raw[:100]}")
        return ClassifierResult(raw_response=raw, error="JSON parse failed")


def _rule_based_fallback(code: str) -> ClassifierResult:
    code_lower = code.lower()
    found = []
    score = 0.0

    rules = {
        "PowerShell 다운로더":  ["invoke-webrequest", "downloadfile", "downloadstring", "webclient"],
        "원격 셸 / 리버스 셸":   ["bash -i", "nc -e", "/bin/sh", "socket.connect"],
        "프로세스 인젝션":       ["virtualalloc", "writeprocessmemory", "createremotethread"],
        "자격증명 탈취":         ["mimikatz", "sekurlsa", "lsass", "credential"],
        "지속성 설치":           ["currentversion\\run", "schtasks /create", "crontab"],
        "C2 통신":              ["while true", "while(1)", "time.sleep", "requests.get"],
        "난독화 실행":           ["iex(", "invoke-expression", "eval(base64", "exec(compile"],
        "파일 암호화":           ["aes", "encrypt", ".encrypt(", "cryptography"],
        "권한 상승":             ["uac", "runas", "sudo", "privilege"],
        "정찰 / 시스템 열거":    ["whoami", "ipconfig", "netstat", "systeminfo"],
    }

    for pattern, keywords in rules.items():
        if any(kw in code_lower for kw in keywords):
            found.append(pattern)
            score = min(score + 0.15, 1.0)

    return ClassifierResult(
        patterns_found=found,
        confidence=round(score, 2),
        brief_reason=f"규칙 기반 폴백: {len(found)}개 패턴 탐지",
    )
