# backend/security/schemas.py
from __future__ import annotations
from pydantic import BaseModel, ConfigDict
from typing import Optional
from enum import Enum


class RiskLevel(str, Enum):
    SAFE     = "safe"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class MitreTechnique(BaseModel):
    technique_id: str
    name: str
    tactic: str
    url: str = ""


class LocalModelOutput(BaseModel):
    risk_score: float
    risk_level: RiskLevel
    pattern_labels: list[str] = []
    obfuscation_techniques: list[str] = []
    obfuscation_score: float = 0.0
    entropy: float = 0.0
    evidence: list[str] = []
    llm_required: bool = False


class LLMReport(BaseModel):
    attack_chain: list[str] = []
    mitre_techniques: list[MitreTechnique] = []
    recommendation: str = ""
    summary: str = ""
    token_usage: int = 0


class AnalysisResult(BaseModel):
    filename: str
    file_size_bytes: int
    lang_hint: str
    line_count: int
    truncated: bool
    local: LocalModelOutput
    llm: Optional[LLMReport] = None
    llm_skipped: bool = False
    processing_time_ms: int = 0


class AnalyzeResponse(BaseModel):
    success: bool
    result: Optional[AnalysisResult] = None
    error: Optional[str] = None


class HealthResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    status: str
    ollama_available: bool
    model_loaded: str
