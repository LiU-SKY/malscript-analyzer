"use client";
import { useState, useEffect, useCallback } from "react";
import {
  fetchSystemStatus, SystemStatus,
  fetchAllLabs, LabSummary,
  fetchAllResults, ResultSummary,
  stopLab, deleteResult,
} from "@/lib/api";
import {
  loadLabHistory, loadScenarioHistory, loadSimHistory,
  deleteLabHistory, deleteScenarioHistory, deleteSimHistory,
  LabHistoryEntry, ScenarioHistoryEntry, SimHistoryEntry,
} from "@/lib/storage";

// ── 위험도/상태 색상 (시맨틱 색상 - 의도적 하드코딩) ──────────────────────────
const RISK_COLOR: Record<string, string> = {
  critical: "#ef4444", high: "#f97316", medium: "#f59e0b", low: "#4ade80", safe: "#4ade80",
};
const riskColor = (r: string) => RISK_COLOR[r.toLowerCase()] ?? "var(--ink-subtle)";

// ── 공통 소형 컴포넌트 ──────────────────────────────────────────────────────
function RiskBadge({ level }: { level: string }) {
  const c = riskColor(level);
  return (
    <span style={{
      color: c, border: `1px solid ${c}33`, borderRadius: "var(--radius-xs)",
      padding: "2px 7px", fontSize: "0.68rem", fontWeight: 600,
      textTransform: "uppercase" as const, letterSpacing: "0.04em", flexShrink: 0,
    }}>
      {level}
    </span>
  );
}

function StatusBadge({ status }: { status: string }) {
  const ok = status === "running";
  const color = ok ? "#4ade80" : status === "error" ? "#f87171" : "var(--ink-tertiary)";
  return (
    <span style={{
      color, border: `1px solid ${color}33`, borderRadius: "var(--radius-xs)",
      padding: "2px 7px", fontSize: "0.68rem",
    }}>
      {status}
    </span>
  );
}

function MetricBar({ pct, color, skeleton }: { pct: number; color: string; skeleton?: boolean }) {
  return (
    <div style={{ background: "var(--surface-2)", borderRadius: 3, overflow: "hidden", height: 5, flex: 1 }}>
      <div style={{
        width: skeleton ? "100%" : `${Math.min(pct, 100)}%`,
        background: skeleton ? "var(--surface-3)" : color,
        height: "100%",
        transition: skeleton ? "none" : "width 0.6s ease, background 0.3s",
        animation: skeleton ? "skeleton-pulse 1.4s ease-in-out infinite" : "none",
      }} />
    </div>
  );
}

function Metric({ label, pct, used, total, unit, skeleton }: {
  label: string; pct: number; used: number; total: number; unit: string; skeleton?: boolean;
}) {
  const color = pct > 85 ? "#ef4444" : pct > 60 ? "#f59e0b" : "var(--primary)";
  return (
    <div style={{ marginBottom: "1.1rem" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 5 }}>
        <span style={{ fontSize: "0.8rem", color: "var(--ink-muted)", fontWeight: 500 }}>{label}</span>
        <span style={{ fontSize: "0.75rem", color: skeleton ? "var(--ink-tertiary)" : color, fontFamily: "var(--font-mono)",
          transition: "color 0.3s" }}>
          {skeleton ? "─ / ─" : `${used.toFixed(1)} / ${total.toFixed(1)} ${unit} (${pct.toFixed(1)}%)`}
        </span>
      </div>
      <MetricBar pct={pct} color={color} skeleton={skeleton} />
    </div>
  );
}

// ── Tab 1: System ──────────────────────────────────────────────────────────
function SystemTab() {
  const [status, setStatus] = useState<SystemStatus | null>(null);
  const [error,  setError]  = useState("");
  // firstLoad: true until we get the first successful response
  const [firstLoad, setFirstLoad] = useState(true);

  const refresh = useCallback(() => {
    fetchSystemStatus()
      .then(s  => { setStatus(s); setError(""); setFirstLoad(false); })
      .catch(e => { setError(e.message); setFirstLoad(false); });
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 5000);
    return () => clearInterval(id);
  }, [refresh]);

  // Hard error with no prior data — show error banner
  if (!firstLoad && error && !status) return (
    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem",
      padding: "0.75rem 1rem", background: "rgba(239,68,68,0.06)",
      border: "1px solid rgba(239,68,68,0.2)", borderRadius: "var(--radius-sm)" }}>
      <span style={{ color: "#f87171", fontSize: "0.75rem" }}>●</span>
      <span style={{ color: "var(--ink-subtle)", fontSize: "0.85rem" }}>백엔드 연결 실패 — {error}</span>
    </div>
  );

  // ── Always render the full structure. When status is null (first load),
  //    pass skeleton=true so bars pulse at 0% and numbers show "─ / ─".
  //    Once status arrives the bars animate from 0% to real value via CSS transition.
  const sk = firstLoad || !status;   // skeleton mode
  const s  = status;

  const cpuPct    = s?.cpu_percent  ?? 0;
  const memPct    = s?.mem_percent  ?? 0;
  const memUsed   = s ? s.mem_used_mb  / 1024 : 0;
  const memTotal  = s ? s.mem_total_mb / 1024 : 0;
  const diskPct   = s?.disk_percent ?? 0;
  const diskUsed  = s?.disk_used_gb ?? 0;
  const diskTotal = s?.disk_total_gb ?? 0;

  return (
    <div>
      {/* 서비스 상태 */}
      <div style={{ display: "flex", alignItems: "center", gap: "0.6rem", marginBottom: "1.25rem", flexWrap: "wrap" as const }}>
        {[
          { on: s?.backend_running ?? false, label: "FastAPI" },
          { on: s?.ollama_running  ?? false, label: "Ollama"  },
        ].map(({ on, label }) => (
          <span key={label} style={{
            display: "inline-flex", alignItems: "center", gap: "0.35rem",
            padding: "0.22rem 0.7rem", borderRadius: "var(--radius-xs)",
            background: sk ? "var(--surface-2)" : on ? "rgba(74,222,128,0.1)" : "rgba(239,68,68,0.1)",
            color: sk ? "var(--ink-tertiary)" : on ? "#4ade80" : "#f87171",
            border: `1px solid ${sk ? "var(--hairline)" : on ? "rgba(74,222,128,0.25)" : "rgba(239,68,68,0.25)"}`,
            fontSize: "0.78rem", fontWeight: 500,
            transition: "background 0.3s, color 0.3s, border-color 0.3s",
            animation: sk ? "skeleton-pulse 1.4s ease-in-out infinite" : "none",
          }}>
            <span style={{ fontSize: "0.45rem" }}>●</span>{label}
          </span>
        ))}
        <span style={{ color: "var(--ink-tertiary)", fontSize: "0.75rem", marginLeft: "auto" }}>
          {s ? `uptime ${s.uptime_seconds.toFixed(0)}s` : "─"}
        </span>
      </div>

      {/* 리소스 메트릭 */}
      <div style={{
        background: "var(--surface-1)", border: "1px solid var(--hairline)",
        borderRadius: "var(--radius-sm)", padding: "1.25rem 1.5rem", marginBottom: "1.5rem",
      }}>
        <Metric label="CPU"    pct={cpuPct}  used={cpuPct}   total={100}      unit="%" skeleton={sk} />
        <Metric label="Memory" pct={memPct}  used={memUsed}  total={memTotal} unit="GB" skeleton={sk} />
        <Metric label="Disk"   pct={diskPct} used={diskUsed} total={diskTotal} unit="GB" skeleton={sk} />
      </div>

      {/* 상위 프로세스 */}
      <div>
        <p className="label" style={{ margin: "0 0 0.6rem" }}>TOP PROCESSES</p>
        <div style={{ border: "1px solid var(--hairline)", borderRadius: "var(--radius-sm)", overflow: "hidden" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.8rem" }}>
            <thead>
              <tr style={{ background: "var(--surface-1)", borderBottom: "1px solid var(--hairline)" }}>
                {["PID", "Name", "CPU %", "Mem MB"].map(h => (
                  <th key={h} style={{
                    textAlign: "left", padding: "0.4rem 0.75rem",
                    color: "var(--ink-tertiary)", fontWeight: 500,
                    letterSpacing: "0.04em", fontSize: "0.7rem",
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sk
                ? Array.from({ length: 5 }, (_, i) => (
                    <tr key={i} style={{ borderBottom: "1px solid var(--hairline)" }}>
                      {([60, 160, 40, 55] as number[]).map((w, j) => (
                        <td key={j} style={{ padding: "0.5rem 0.75rem" }}>
                          <span style={{
                            display: "inline-block", height: "0.7rem",
                            width: w + "px",
                            background: "var(--surface-3)", borderRadius: 3,
                            animation: "skeleton-pulse 1.4s ease-in-out infinite",
                            animationDelay: `${i * 0.07}s`,
                          }} />
                        </td>
                      ))}
                    </tr>
                  ))
                : (s?.top_processes ?? []).map((p, i) => (
                    <tr key={p.pid} style={{
                      borderBottom: i < (s?.top_processes.length ?? 0) - 1 ? "1px solid var(--hairline)" : "none",
                    }}>
                      <td style={{ padding: "0.38rem 0.75rem", color: "var(--ink-tertiary)", fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>{p.pid}</td>
                      <td style={{ padding: "0.38rem 0.75rem", color: "var(--ink-muted)" }}>{p.name}</td>
                      <td style={{ padding: "0.38rem 0.75rem", color: "var(--ink-subtle)", fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>{p.cpu.toFixed(1)}</td>
                      <td style={{ padding: "0.38rem 0.75rem", color: "var(--ink-subtle)", fontFamily: "var(--font-mono)", fontSize: "0.75rem" }}>{p.mem_mb.toFixed(0)}</td>
                    </tr>
                  ))
              }
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── Tab 2: Docker Labs ─────────────────────────────────────────────────────
function DockerLabsTab() {
  const [serverLabs,  setServerLabs]  = useState<LabSummary[]>([]);
  const [historyLabs, setHistoryLabs] = useState<LabHistoryEntry[]>([]);
  const [loading,     setLoading]     = useState(false);
  const [stopping,    setStopping]    = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try { setServerLabs(await fetchAllLabs()); } catch { setServerLabs([]); }
    setHistoryLabs(loadLabHistory());
    setLoading(false);
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const handleStop = async (labId: string) => {
    setStopping(labId);
    try { await stopLab(labId); await refresh(); } catch { /* ignore */ }
    setStopping(null);
  };

  const handleDeleteHistory = (labId: string) => {
    deleteLabHistory(labId);
    setHistoryLabs(loadLabHistory());
  };

  const serverIds = new Set(serverLabs.map(l => l.lab_id));
  const histOnly  = historyLabs.filter(h => !serverIds.has(h.labId));

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.1rem" }}>
        <p className="label" style={{ margin: 0 }}>RUNNING / RECENT LABS</p>
        <button onClick={refresh} className="btn-ghost"
          style={{ padding: "0.25rem 0.65rem", fontSize: "0.75rem" }}>
          {loading ? "…" : "새로고침"}
        </button>
      </div>

      {serverLabs.length === 0 && !loading && (
        <p style={{ color: "var(--ink-tertiary)", fontSize: "0.83rem", margin: "0 0 1rem" }}>
          현재 세션에 생성된 랩이 없습니다.
        </p>
      )}

      {serverLabs.map(lab => (
        <div key={lab.lab_id} style={{
          background: "var(--surface-1)", border: "1px solid var(--hairline)",
          borderRadius: "var(--radius-sm)", padding: "1rem", marginBottom: "0.75rem",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginBottom: "0.6rem" }}>
            <StatusBadge status={lab.status} />
            <span style={{ color: "var(--ink)", fontWeight: 600, fontSize: "0.9rem" }}>{lab.preset_name}</span>
            <code style={{
              color: "var(--ink-tertiary)", fontSize: "0.7rem", marginLeft: "auto",
              fontFamily: "var(--font-mono)",
            }}>{lab.lab_id}</code>
          </div>
          <div style={{
            display: "grid", gridTemplateColumns: "1fr 1fr", gap: "0.3rem",
            fontSize: "0.75rem", color: "var(--ink-subtle)", marginBottom: "0.75rem",
          }}>
            <span>공격자: <code style={{ color: "var(--ink-tertiary)", fontFamily: "var(--font-mono)" }}>{lab.attacker_container_id?.slice(0, 12) ?? "—"}</code></span>
            <span>대상: <code style={{ color: "var(--ink-tertiary)", fontFamily: "var(--font-mono)" }}>{lab.target_container_id?.slice(0, 12) ?? "—"}</code></span>
            <span>포트: {lab.target_ports.join(", ") || "—"}</span>
            {lab.error && <span style={{ color: "#f87171" }}>오류: {lab.error}</span>}
          </div>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <a href={`/simulation?lab_id=${lab.lab_id}`} className="btn-primary"
              style={{ padding: "0.28rem 0.75rem", fontSize: "0.78rem", textDecoration: "none" }}>
              → 시뮬레이션
            </a>
            {lab.status === "running" && (
              <button onClick={() => handleStop(lab.lab_id)} disabled={stopping === lab.lab_id}
                style={{
                  padding: "0.28rem 0.75rem", fontSize: "0.78rem", cursor: "pointer",
                  background: "rgba(239,68,68,0.08)", color: "#f87171",
                  border: "1px solid rgba(239,68,68,0.3)", borderRadius: "var(--radius-xs)",
                }}>
                {stopping === lab.lab_id ? "중지 중…" : "■ Stop"}
              </button>
            )}
          </div>
        </div>
      ))}

      {histOnly.length > 0 && (
        <>
          <p className="label" style={{ margin: "1rem 0 0.5rem" }}>이전 세션 이력</p>
          {histOnly.map(h => (
            <div key={h.labId} style={{
              background: "var(--canvas)", border: "1px solid var(--hairline)",
              borderRadius: "var(--radius-sm)", padding: "0.65rem 0.9rem", marginBottom: "0.4rem",
              display: "flex", alignItems: "center", gap: "0.75rem",
            }}>
              <StatusBadge status={h.status} />
              <span style={{ color: "var(--ink-muted)", fontSize: "0.85rem" }}>{h.presetName}</span>
              <code style={{ color: "var(--ink-tertiary)", fontSize: "0.68rem", fontFamily: "var(--font-mono)" }}>{h.labId}</code>
              <span style={{ color: "var(--ink-tertiary)", fontSize: "0.68rem", marginLeft: "auto" }}>
                {new Date(h.timestamp).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}
              </span>
              <a href={`/simulation?lab_id=${h.labId}`} style={{
                color: "var(--primary)", fontSize: "0.7rem", textDecoration: "none",
                border: "1px solid var(--primary-muted)", borderRadius: "var(--radius-xs)", padding: "1px 7px",
              }}>시뮬레이션</a>
              <button onClick={() => handleDeleteHistory(h.labId)} style={{
                background: "none", border: "none", cursor: "pointer",
                color: "var(--ink-tertiary)", fontSize: "0.78rem", padding: "2px 4px",
              }}>✕</button>
            </div>
          ))}
        </>
      )}
    </div>
  );
}

// ── Tab 3: Analysis Logs ───────────────────────────────────────────────────
function AnalysisLogsTab() {
  const [serverResults,   setServerResults]   = useState<ResultSummary[]>([]);
  const [scenarioHistory, setScenarioHistory] = useState<ScenarioHistoryEntry[]>([]);
  const [simHistory,      setSimHistory]      = useState<SimHistoryEntry[]>([]);
  const [loading,  setLoading]  = useState(false);
  const [deleting, setDeleting] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try { setServerResults(await fetchAllResults()); } catch { setServerResults([]); }
    setScenarioHistory(loadScenarioHistory());
    setSimHistory(loadSimHistory());
    setLoading(false);
  }, []);

  useEffect(() => { refresh(); }, [refresh]);

  const handleDeleteResult = async (id: string) => {
    setDeleting(id);
    try { await deleteResult(id); } catch { /* ignore */ }
    await refresh();
    setDeleting(null);
  };

  const handleDeleteScenario = (id: string) => {
    deleteScenarioHistory(id);
    setScenarioHistory(loadScenarioHistory());
  };

  const handleDeleteSim = (id: string) => {
    deleteSimHistory(id);
    setSimHistory(loadSimHistory());
  };

  function SectionTitle({ text }: { text: string }) {
    return (
      <div style={{ borderBottom: "1px solid var(--hairline)", paddingBottom: "0.4rem", marginBottom: "0.6rem" }}>
        <p className="label" style={{ margin: 0 }}>{text}</p>
      </div>
    );
  }

  function EmptyRow({ msg }: { msg: string }) {
    return <p style={{ color: "var(--ink-tertiary)", fontSize: "0.82rem", marginBottom: "1rem" }}>{msg}</p>;
  }

  function LogLink({ href, label, variant = "default" }: { href: string; label: string; variant?: string }) {
    const col  = variant === "purple" ? "var(--primary-hover)" : "var(--primary)";
    return (
      <a href={href} style={{
        color: col, fontSize: "0.7rem", textDecoration: "none",
        border: "1px solid var(--primary-muted)", borderRadius: "var(--radius-xs)", padding: "1px 7px",
      }}>{label}</a>
    );
  }

  const rowStyle: React.CSSProperties = {
    display: "flex", alignItems: "center", gap: "0.65rem",
    padding: "0.55rem 0.75rem", background: "var(--surface-1)",
    borderRadius: "var(--radius-xs)", marginBottom: "0.35rem",
    border: "1px solid var(--hairline)",
  };

  return (
    <div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.1rem" }}>
        <p className="label" style={{ margin: 0 }}>분석 / 시나리오 / 시뮬레이션 로그</p>
        <button onClick={refresh} className="btn-ghost"
          style={{ padding: "0.25rem 0.65rem", fontSize: "0.75rem" }}>
          {loading ? "…" : "새로고침"}
        </button>
      </div>

      {/* 분석 결과 */}
      <SectionTitle text={`분석 결과 (${serverResults.length})`} />
      {serverResults.length === 0 && !loading && <EmptyRow msg="분석된 파일이 없습니다." />}
      {serverResults.map(r => (
        <div key={r.result_id} style={rowStyle}>
          <RiskBadge level={r.risk_level} />
          <span style={{ color: "var(--ink)", fontSize: "0.85rem", flex: 1,
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" as const }}>
            {r.filename}
          </span>
          <span style={{ color: "var(--ink-subtle)", fontSize: "0.72rem", flexShrink: 0 }}>{r.lang_hint}</span>
          <span style={{ color: riskColor(r.risk_level), fontSize: "0.72rem", fontFamily: "var(--font-mono)", flexShrink: 0 }}>
            {r.risk_score.toFixed(2)}
          </span>
          <span style={{ color: "var(--ink-tertiary)", fontSize: "0.68rem", fontFamily: "var(--font-mono)", flexShrink: 0 }}>
            {r.processing_time_ms}ms
          </span>
          <div style={{ display: "flex", gap: "0.4rem", flexShrink: 0 }}>
            <LogLink href={`/?result_id=${r.result_id}`} label="보기" />
            {r.scenario_id && <LogLink href={`/scenario?scenario_id=${r.scenario_id}`} label="시나리오" variant="purple" />}
            <button onClick={() => handleDeleteResult(r.result_id)} disabled={deleting === r.result_id}
              style={{ background: "none", border: "none", cursor: "pointer",
                color: "var(--ink-tertiary)", fontSize: "0.75rem", padding: "2px 4px" }}>
              {deleting === r.result_id ? "…" : "✕"}
            </button>
          </div>
        </div>
      ))}

      {/* 시나리오 이력 */}
      <SectionTitle text={`시나리오 이력 (${scenarioHistory.length})`} />
      {scenarioHistory.length === 0 && <EmptyRow msg="생성된 시나리오가 없습니다." />}
      {scenarioHistory.map(s => (
        <div key={s.scenarioId} style={rowStyle}>
          <span style={{
            color: RISK_COLOR[s.difficulty] ?? "var(--ink-subtle)",
            border: `1px solid ${(RISK_COLOR[s.difficulty] ?? "#aaa")}33`,
            borderRadius: "var(--radius-xs)", padding: "2px 6px",
            fontSize: "0.68rem", fontWeight: 600, textTransform: "uppercase" as const,
            letterSpacing: "0.04em", flexShrink: 0,
          }}>{s.difficulty}</span>
          <span style={{ color: "var(--ink)", fontSize: "0.85rem", flex: 1,
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" as const }}>
            {s.title}
          </span>
          <span style={{ color: "var(--ink-subtle)", fontSize: "0.72rem", flexShrink: 0 }}>{s.stepCount}단계</span>
          <span style={{ color: "var(--ink-tertiary)", fontSize: "0.68rem", flexShrink: 0 }}>
            {new Date(s.timestamp).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}
          </span>
          <div style={{ display: "flex", gap: "0.4rem", flexShrink: 0 }}>
            <LogLink href={`/scenario?scenario_id=${s.scenarioId}`} label="보기" />
            <LogLink href={`/simulation?scenario_id=${s.scenarioId}`} label="시뮬레이션" variant="purple" />
            <button onClick={() => handleDeleteScenario(s.scenarioId)} style={{
              background: "none", border: "none", cursor: "pointer",
              color: "var(--ink-tertiary)", fontSize: "0.75rem", padding: "2px 4px",
            }}>✕</button>
          </div>
        </div>
      ))}

      {/* 시뮬레이션 이력 */}
      <SectionTitle text={`시뮬레이션 이력 (${simHistory.length})`} />
      {simHistory.length === 0 && <EmptyRow msg="실행된 시뮬레이션이 없습니다." />}
      {simHistory.map(s => (
        <div key={s.simId} style={rowStyle}>
          <span style={{
            color: s.failedCount > 0 ? "#f97316" : "#4ade80",
            border: `1px solid ${s.failedCount > 0 ? "rgba(249,115,22,0.3)" : "rgba(74,222,128,0.3)"}`,
            borderRadius: "var(--radius-xs)", padding: "2px 5px", fontSize: "0.68rem", flexShrink: 0,
          }}>
            {s.successCount}✓ {s.failedCount}✗
          </span>
          <span style={{ color: "var(--ink)", fontSize: "0.85rem", flex: 1,
            overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" as const }}>
            {s.scenarioTitle}
          </span>
          <span style={{ color: "var(--ink-subtle)", fontSize: "0.72rem", flexShrink: 0 }}>{s.totalSteps}단계</span>
          {s.labId !== "dry-run" ? (
            <code style={{
              color: "var(--primary)", fontSize: "0.65rem", fontFamily: "var(--font-mono)",
              background: "var(--primary-glow)", padding: "1px 5px", borderRadius: 3, flexShrink: 0,
            }}>{s.labId}</code>
          ) : (
            <span style={{ color: "var(--ink-tertiary)", fontSize: "0.68rem", flexShrink: 0 }}>DRY-RUN</span>
          )}
          <span style={{ color: "var(--ink-tertiary)", fontSize: "0.68rem", flexShrink: 0 }}>
            {new Date(s.timestamp).toLocaleString("ko-KR", { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" })}
          </span>
          <div style={{ display: "flex", gap: "0.4rem", flexShrink: 0 }}>
            <LogLink href={`/simulation?scenario_id=${s.scenarioId}`} label="재실행" />
            <button onClick={() => handleDeleteSim(s.simId)} style={{
              background: "none", border: "none", cursor: "pointer",
              color: "var(--ink-tertiary)", fontSize: "0.75rem", padding: "2px 4px",
            }}>✕</button>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────
type Tab = "system" | "docker" | "logs";

export default function MonitorPage() {
  const [tab, setTab] = useState<Tab>("system");

  const tabs: { id: Tab; label: string }[] = [
    { id: "system", label: "System" },
    { id: "docker", label: "Docker Labs" },
    { id: "logs",   label: "Analysis Logs" },
  ];

  return (
    <main style={{
      padding: "2rem", maxWidth: 960, margin: "0 auto",
      fontFamily: "var(--font-sans)", color: "var(--ink)",
    }}>
      {/* 페이지 헤더 */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: "1.75rem" }}>
        <div>
          <h1 style={{
            color: "var(--ink)", margin: "0 0 0.25rem",
            fontSize: "1.4rem", fontWeight: 600, letterSpacing: "-0.02em",
          }}>Monitor</h1>
          <p style={{ color: "var(--ink-subtle)", margin: 0, fontSize: "0.83rem" }}>
            시스템 리소스 · Docker 랩 · 분석 로그
          </p>
        </div>
        <a href="/" className="btn-ghost" style={{ textDecoration: "none", fontSize: "0.82rem" }}>
          ← 분석으로
        </a>
      </div>

      {/* 탭 바 */}
      <div style={{ display: "flex", marginBottom: "1.5rem", borderBottom: "1px solid var(--hairline)" }}>
        {tabs.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            padding: "0.5rem 1.1rem", background: "none", border: "none",
            cursor: "pointer", fontFamily: "var(--font-sans)",
            fontSize: "0.85rem", fontWeight: tab === t.id ? 500 : 400,
            color: tab === t.id ? "var(--ink)" : "var(--ink-subtle)",
            borderBottom: tab === t.id ? "2px solid var(--primary)" : "2px solid transparent",
            marginBottom: "-1px", transition: "color 0.15s",
          }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* 탭 내용 — 활성 탭만 마운트 (불필요한 API 폴링 방지) */}
      {tab === "system" && <SystemTab />}
      {tab === "docker" && <DockerLabsTab />}
      {tab === "logs"   && <AnalysisLogsTab />}
    </main>
  );
}
