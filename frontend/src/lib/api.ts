// frontend/src/lib/api.ts
const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type RiskLevel = "safe" | "medium" | "high" | "critical";

export interface MitreTechnique {
  technique_id: string;
  name: string;
  tactic: string;
  url: string;
}

export interface LocalModelOutput {
  risk_score: number;
  risk_level: RiskLevel;
  pattern_labels: string[];
  obfuscation_techniques: string[];
  obfuscation_score: number;
  entropy: number;
  evidence: string[];
  llm_required: boolean;
}

export interface LLMReport {
  attack_chain: string[];
  mitre_techniques: MitreTechnique[];
  recommendation: string;
  summary: string;
  token_usage: number;
}

export interface AnalysisResult {
  filename: string;
  file_size_bytes: number;
  lang_hint: string;
  line_count: number;
  truncated: boolean;
  local: LocalModelOutput;
  llm: LLMReport | null;
  llm_skipped: boolean;
  processing_time_ms: number;
}

export interface AnalyzeResponse {
  success: boolean;
  result: AnalysisResult | null;
  error: string | null;
}

export interface HealthResponse {
  status: string;
  ollama_available: boolean;
  model_loaded: string;
}

export async function analyzeFile(file: File): Promise<AnalyzeResponse> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${BASE}/analyze`, { method: "POST", body: form });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail ?? "분석 실패");
  }
  return res.json();
}

export async function fetchHealth(): Promise<HealthResponse> {
  const res = await fetch(`${BASE}/health`, { cache: "no-store" });
  if (!res.ok) throw new Error("서버 연결 실패");
  return res.json();
}

export const RISK_META: Record<RiskLevel, { label: string; color: string; glow: string }> = {
  safe:     { label: "SAFE",     color: "#22c55e", glow: "rgba(34,197,94,0.25)" },
  medium:   { label: "MEDIUM",   color: "#f59e0b", glow: "rgba(245,158,11,0.25)" },
  high:     { label: "HIGH",     color: "#f97316", glow: "rgba(249,115,22,0.30)" },
  critical: { label: "CRITICAL", color: "#ef4444", glow: "rgba(239,68,68,0.35)" },
};

export function formatBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 / 1024).toFixed(2)} MB`;
}
