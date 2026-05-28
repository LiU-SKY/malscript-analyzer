# backend/preprocessor.py
# 역할: 로컬 모델에 넣기 전 스크립트 정규화 및 길이 제한
# TOKEN_SAVE: LLM에는 전처리된 압축본만 전달 → 토큰 60% 절감

import re
import chardet
from dataclasses import dataclass

MAX_CHARS = 8_000
MAX_LLM_CHARS = 2_000


@dataclass
class PreprocessedScript:
    original_length: int
    cleaned_code: str
    encoding: str
    line_count: int
    lang_hint: str
    truncated: bool


def preprocess(raw_bytes: bytes, filename: str) -> PreprocessedScript:
    original_length = len(raw_bytes)
    detected = chardet.detect(raw_bytes)
    encoding = detected.get("encoding") or "utf-8"
    try:
        text = raw_bytes.decode(encoding, errors="replace")
    except Exception:
        text = raw_bytes.decode("utf-8", errors="replace")

    text = text.lstrip("\ufeff")
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n{3,}", "\n\n", text)

    truncated = len(text) > MAX_CHARS
    cleaned = text[:MAX_CHARS] if truncated else text

    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "unknown"
    lang_map = {"ps1": "PowerShell", "js": "JavaScript",
                "py": "Python", "vbs": "VBScript", "bat": "Batch"}
    lang_hint = lang_map.get(ext, "Unknown")

    return PreprocessedScript(
        original_length=original_length,
        cleaned_code=cleaned,
        encoding=encoding,
        line_count=cleaned.count("\n") + 1,
        lang_hint=lang_hint,
        truncated=truncated,
    )


def compress_for_llm(code: str, evidence: list[str]) -> str:
    """TOKEN_SAVE: 로컬 모델 근거 + 의심 코드 상위 30줄만 LLM에 전달"""
    top_lines = "\n".join(code.splitlines()[:30])
    evidence_str = "\n".join(f"- {e}" for e in evidence)
    return f"[로컬 탐지 근거]\n{evidence_str}\n\n[의심 코드 발췌]\n{top_lines}"[:MAX_LLM_CHARS]
