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


# Phase 1 -- Vulnerability schemas
class VulnItem(BaseModel):
    cwe_id: str
    cwe_name: str
    impact_type: str
    severity: str
    cvss_estimate: float
    description: str
    source_technique: str


class VulnerabilityReport(BaseModel):
    vulnerabilities: list[VulnItem] = []
    highest_severity: str = "NONE"
    impact_types: list[str] = []
    cwe_ids: list[str] = []


# Phase 2 -- Scenario schemas
class ScenarioStep(BaseModel):
    step_number: int
    title: str
    description: str
    command: str = ""           # 표시용 원본 명령어 (Windows 등 플랫폼 네이티브)
    exec_command: str = ""      # Docker Linux 컨테이너에서 실제 실행할 명령어
    mitre_technique: str = ""
    expected_outcome: str = ""


class DockerConfig(BaseModel):
    attacker_image: str = "kalilinux/kali-rolling"
    target_image: str = "webgoat/goat-and-wolf"
    target_ports: list[int] = []
    env_vars: dict[str, str] = {}
    preset_name: str = ""


class AttackScenario(BaseModel):
    scenario_id: str
    title: str
    description: str
    difficulty: str = "MEDIUM"
    steps: list[ScenarioStep] = []
    defenses: list[str] = []
    docker_config: DockerConfig = DockerConfig()
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
    vulnerabilities: Optional[VulnerabilityReport] = None
    scenario_id: Optional[str] = None
    # OS 감지 결과
    target_os: str = "unknown"          # "windows" | "linux" | "unknown"
    os_confidence: str = "low"          # "high" | "medium" | "low"
    os_reason: str = ""                 # 감지 근거 설명


class AnalyzeResponse(BaseModel):
    success: bool
    result: Optional[AnalysisResult] = None
    error: Optional[str] = None
    result_id: Optional[str] = None   # 분석 결과 캐시 키 (시나리오 생성에 필요)


class HealthResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())

    status: str
    ollama_available: bool
    model_loaded: str
