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
  vulnerabilities?: VulnerabilityReport;
  scenario_id?: string;
  target_os?: "windows" | "linux" | "unknown";
  os_confidence?: "high" | "medium" | "low";
  os_reason?: string;
}

export interface AnalyzeResponse {
  success: boolean;
  result: AnalysisResult | null;
  error: string | null;
  result_id: string | null;
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

export interface VulnItem {
  cwe_id: string;
  cwe_name: string;
  impact_type: string;
  severity: string;
  cvss_estimate: number;
  description: string;
  source_technique: string;
}

export interface VulnerabilityReport {
  vulnerabilities: VulnItem[];
  highest_severity: string;
  impact_types: string[];
  cwe_ids: string[];
}

export interface ScenarioStep {
  step_number: number;
  title: string;
  description: string;
  command: string;
  exec_command: string;
  mitre_technique: string;
  expected_outcome: string;
}

export interface DockerConfig {
  attacker_image: string;
  target_image: string;
  target_ports: number[];
  env_vars: Record<string, string>;
  preset_name: string;
}

export interface AttackScenario {
  scenario_id: string;
  title: string;
  description: string;
  difficulty: string;
  steps: ScenarioStep[];
  defenses: string[];
  docker_config: DockerConfig;
  token_usage: number;
}

export interface LabPreset {
  name: string;
  description: string;
  attacker: string;
  target: string;
}

export interface LabEnvironment {
  lab_id: string;
  preset_name: string;
  status: string;
  target_ports: number[];
  attacker_container_id: string | null;
  target_container_id: string | null;
  error: string;
}

export interface SimEvent {
  event_type: string;
  step: number;
  message: string;
  detail: string;
  timestamp: number;
}

export interface SimResult {
  sim_id: string;
  scenario_id: string;
  lab_id: string;
  status: string;
  steps_done: number;
  steps_total: number;
  error: string;
  event_count: number;
}

export interface SystemStatus {
  cpu_percent: number;
  mem_total_mb: number;
  mem_used_mb: number;
  mem_percent: number;
  disk_total_gb: number;
  disk_used_gb: number;
  disk_percent: number;
  ollama_running: boolean;
  backend_running: boolean;
  uptime_seconds: number;
  top_processes: { pid: number; name: string; cpu: number; mem_mb: number }[];
}

export async function fetchVulnerabilities(resultId: string): Promise<VulnerabilityReport> {
  const res = await fetch(`${BASE}/vulnerabilities/${resultId}`);
  if (!res.ok) throw new Error("취약점 데이터 없음");
  return res.json();
}

export async function generateScenario(resultId: string): Promise<AttackScenario> {
  const res = await fetch(`${BASE}/scenarios/generate?result_id=${resultId}`, { method: "POST" });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail ?? `시나리오 생성 실패 (${res.status})`);
  }
  return res.json();
}

export async function fetchScenario(scenarioId: string): Promise<AttackScenario> {
  const res = await fetch(`${BASE}/scenarios/${scenarioId}`);
  if (!res.ok) {
    const body = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(body.detail ?? `시나리오 없음 (${res.status})`);
  }
  return res.json();
}

export async function fetchDockerStatus(): Promise<{ available: boolean; reason: string }> {
  try {
    const res = await fetch(`${BASE}/labs/docker-status`, { cache: "no-store" });
    if (!res.ok) return { available: false, reason: "API error" };
    return res.json();
  } catch {
    return { available: false, reason: "Backend unreachable" };
  }
}

export async function fetchLabPresets(): Promise<LabPreset[]> {
  const res = await fetch(`${BASE}/labs/presets`);
  if (!res.ok) throw new Error("프리셋 목록 실패");
  return res.json();
}

export async function createLab(presetName: string): Promise<LabEnvironment> {
  const res = await fetch(`${BASE}/labs/create?preset_name=${presetName}`, { method: "POST" });
  if (!res.ok) throw new Error("랩 생성 실패");
  return res.json();
}

export interface LabProgressEvent {
  event: string;
  message: string;
}

export function openLabCreateSSE(
  presetName: string,
  onEvent: (evt: LabProgressEvent) => void,
): Promise<() => void> {
  return new Promise((resolve) => {
    const controller = new AbortController();
    const close = () => controller.abort();
    resolve(close);

    fetch(`${BASE}/labs/create/stream?preset_name=${presetName}`, {
      method: "POST",
      signal: controller.signal,
    }).then(async (res) => {
      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const parts = buf.split("\n\n");
        buf = parts.pop() ?? "";
        for (const part of parts) {
          const line = part.replace(/^data:\s*/, "").trim();
          if (!line) continue;
          try {
            const evt = JSON.parse(line) as LabProgressEvent;
            onEvent(evt);
          } catch (_) {}
        }
      }
    }).catch(() => {});
  });
}

export async function stopLab(labId: string): Promise<void> {
  await fetch(`${BASE}/labs/${labId}`, { method: "DELETE" });
}

export async function fetchSystemStatus(): Promise<SystemStatus> {
  const res = await fetch(`${BASE}/system/status`, { cache: "no-store" });
  if (!res.ok) throw new Error("시스템 상태 실패");
  return res.json();
}

export function openSimulationSSE(
  scenarioId: string,
  onEvent: (evt: SimEvent) => void,
  labId?: string,
): () => void {
  const base = `${BASE}/simulation/run?scenario_id=${scenarioId}`;
  const url  = labId ? `${base}&lab_id=${labId}` : base;
  const es   = new EventSource(url);
  es.onmessage = (e) => {
    try {
      const evt: SimEvent = JSON.parse(e.data);
      onEvent(evt);
      if (evt.event_type === "complete" || evt.event_type === "error") es.close();
    } catch (_) {}
  };
  es.onerror = () => es.close();
  return () => es.close();
}

export interface LabSummary {
  lab_id: string;
  preset_name: string;
  status: string;
  target_ports: number[];
  attacker_container_id: string | null;
  target_container_id: string | null;
  error: string;
}

export interface ResultSummary {
  result_id: string;
  filename: string;
  lang_hint: string;
  risk_level: string;
  risk_score: number;
  llm_skipped: boolean;
  scenario_id: string | null;
  processing_time_ms: number;
}

export async function fetchAllLabs(): Promise<LabSummary[]> {
  const r = await fetch(`${BASE}/labs`);
  if (!r.ok) throw new Error("labs fetch failed");
  return r.json();
}

export async function fetchAllResults(): Promise<ResultSummary[]> {
  const r = await fetch(`${BASE}/results`);
  if (!r.ok) throw new Error("results fetch failed");
  return r.json();
}

export async function deleteResult(resultId: string): Promise<void> {
  const r = await fetch(`${BASE}/results/${resultId}`, { method: "DELETE" });
  if (!r.ok) throw new Error("delete failed");
}

export interface DefenseAction {
  id: string;
  name: string;
  description: string;
  has_command: boolean;
}

export interface DefenseResult {
  defense_id: string;
  defense_name: string;
  output: string;
  is_dry_run: boolean;
  success: boolean;
}

export interface StepResult {
  step_number: number;
  title: string;
  mitre_technique: string;
  command: string;
  exec_command: string;
  output: string;
  is_dry_run: boolean;
  defense_blocked: boolean;
  defense_keyword: string;
  expected_outcome: string;
}

export async function fetchDefenses(mitre: string): Promise<DefenseAction[]> {
  const res = await fetch(`${BASE}/simulation/defenses/${encodeURIComponent(mitre)}`);
  if (!res.ok) return [];
  return res.json();
}

export async function applyDefense(
  labId: string,
  mitre: string,
  defenseId: string,
): Promise<DefenseResult> {
  const res = await fetch(`${BASE}/simulation/defend`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ lab_id: labId, mitre, defense_id: defenseId }),
  });
  if (!res.ok) throw new Error("방어 실행 실패");
  return res.json();
}

export async function runStep(
  scenarioId: string,
  stepNumber: number,
  labId: string,
): Promise<StepResult> {
  const res = await fetch(`${BASE}/simulation/run-step`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenario_id: scenarioId, step_number: stepNumber, lab_id: labId }),
  });
  if (!res.ok) throw new Error("단계 실행 실패");
  return res.json();
}
