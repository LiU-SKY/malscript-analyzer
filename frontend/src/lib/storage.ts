// frontend/src/lib/storage.ts
// Centralised localStorage layer — all persistent state lives here.

// ── Keys ──────────────────────────────────────────────────────────────────
const K = {
  SCENARIO_HISTORY: "ms_scenario_history",
  LAB_HISTORY:      "ms_lab_history",
  SIM_HISTORY:      "ms_sim_history",
  CUR_SCENARIO_ID:  "ms_cur_scenario_id",
  CUR_LAB_ID:       "ms_cur_lab_id",
  CUR_PRESET:       "ms_cur_preset",
  CUR_RESULT_ID:    "ms_cur_result_id",
} as const;

// ── Generic helpers ───────────────────────────────────────────────────────
function load<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(key);
    return raw ? (JSON.parse(raw) as T) : fallback;
  } catch { return fallback; }
}
function save<T>(key: string, val: T): void {
  try { localStorage.setItem(key, JSON.stringify(val)); } catch {}
}

// ── Types ─────────────────────────────────────────────────────────────────
export interface ScenarioHistoryEntry {
  scenarioId:  string;
  title:       string;
  difficulty:  string;
  stepCount:   number;
  timestamp:   number;
}

export interface LabHistoryEntry {
  labId:       string;
  presetName:  string;
  presetDesc:  string;
  timestamp:   number;
  status:      string;   // "running" | "stopped" | "error"
  targetPorts: number[];
}

export interface StoredSimEvent {
  event_type: string;
  step:       number;
  message:    string;
  detail:     string;
}

export interface SimHistoryEntry {
  simId:         string;
  scenarioId:    string;
  scenarioTitle: string;
  labId:         string;
  timestamp:     number;
  totalSteps:    number;
  successCount:  number;
  failedCount:   number;
  events:        StoredSimEvent[];
}

// ── Scenario history ──────────────────────────────────────────────────────
export function loadScenarioHistory(): ScenarioHistoryEntry[] {
  return load<ScenarioHistoryEntry[]>(K.SCENARIO_HISTORY, []);
}
export function pushScenarioHistory(e: ScenarioHistoryEntry): void {
  const prev = loadScenarioHistory().filter(x => x.scenarioId !== e.scenarioId);
  save(K.SCENARIO_HISTORY, [e, ...prev].slice(0, 20));
}
export function deleteScenarioHistory(id: string): void {
  save(K.SCENARIO_HISTORY, loadScenarioHistory().filter(x => x.scenarioId !== id));
}

// ── Lab history ───────────────────────────────────────────────────────────
export function loadLabHistory(): LabHistoryEntry[] {
  return load<LabHistoryEntry[]>(K.LAB_HISTORY, []);
}
export function pushLabHistory(e: LabHistoryEntry): void {
  const prev = loadLabHistory().filter(x => x.labId !== e.labId);
  save(K.LAB_HISTORY, [e, ...prev].slice(0, 10));
}
export function updateLabHistoryStatus(labId: string, status: string): void {
  save(K.LAB_HISTORY, loadLabHistory().map(x =>
    x.labId === labId ? { ...x, status } : x
  ));
}
export function deleteLabHistory(id: string): void {
  save(K.LAB_HISTORY, loadLabHistory().filter(x => x.labId !== id));
}

// ── Simulation history ────────────────────────────────────────────────────
export function loadSimHistory(): SimHistoryEntry[] {
  return load<SimHistoryEntry[]>(K.SIM_HISTORY, []);
}
export function pushSimHistory(e: SimHistoryEntry): void {
  const prev = loadSimHistory().filter(x => x.simId !== e.simId);
  save(K.SIM_HISTORY, [e, ...prev].slice(0, 15));
}
export function deleteSimHistory(id: string): void {
  save(K.SIM_HISTORY, loadSimHistory().filter(x => x.simId !== id));
}

// ── Current selections (shared across pages) ──────────────────────────────
export function getCurScenarioId(): string  { return load(K.CUR_SCENARIO_ID, ""); }
export function setCurScenarioId(v: string) { save(K.CUR_SCENARIO_ID, v); }
export function getCurLabId(): string       { return load(K.CUR_LAB_ID, ""); }
export function setCurLabId(v: string)      { save(K.CUR_LAB_ID, v); }
export function getCurPreset(): string      { return load(K.CUR_PRESET, "lightweight-test"); }
export function setCurPreset(v: string)     { save(K.CUR_PRESET, v); }
export function getCurResultId(): string    { return load(K.CUR_RESULT_ID, ""); }
export function setCurResultId(v: string)   { save(K.CUR_RESULT_ID, v); }
