"use client";
export const dynamic = "force-dynamic";
import { useState, useEffect, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { generateScenario, fetchScenario, AttackScenario } from "@/lib/api";
import {
  loadScenarioHistory, pushScenarioHistory, deleteScenarioHistory,
  ScenarioHistoryEntry, getCurScenarioId, setCurScenarioId, setCurResultId,
} from "@/lib/storage";

const DIFF_COLOR: Record<string, string> = {
  LOW: "#4ade80", MEDIUM: "#fbbf24", HIGH: "#fb923c", CRITICAL: "#f87171",
};
const DIFF_BG: Record<string, string> = {
  LOW: "rgba(74,222,128,0.07)", MEDIUM: "rgba(251,191,36,0.07)",
  HIGH: "rgba(251,146,60,0.07)", CRITICAL: "rgba(248,113,113,0.07)",
};
const DIFF_BORDER: Record<string, string> = {
  LOW: "rgba(74,222,128,0.25)", MEDIUM: "rgba(251,191,36,0.25)",
  HIGH: "rgba(251,146,60,0.25)", CRITICAL: "rgba(248,113,113,0.25)",
};

function ScenarioContent() {
  const params = useSearchParams();
  const router = useRouter();

  const [resultId,   setResultId]   = useState(params.get("result_id") ?? "");
  const [scenarioId, setScenarioId] = useState(params.get("scenario_id") ?? "");
  const [scenario,   setScenario]   = useState<AttackScenario | null>(null);
  const [loading,    setLoading]    = useState(false);
  const [error,      setError]      = useState("");
  const [history,    setHistory]    = useState<ScenarioHistoryEntry[]>([]);
  const [histOpen,   setHistOpen]   = useState(false);

  useEffect(() => {
    setHistory(loadScenarioHistory());
    if (!params.get("scenario_id") && !params.get("result_id")) {
      const saved = getCurScenarioId();
      if (saved) setScenarioId(saved);
    }
  }, []);

  useEffect(() => {
    const sid = params.get("scenario_id");
    if (sid) { loadById(sid); return; }
    const rid = params.get("result_id");
    if (rid) { autoGenerate(rid); }
  }, []);

  const saveToHistory = (sc: AttackScenario) => {
    const entry: ScenarioHistoryEntry = {
      scenarioId: sc.scenario_id, title: sc.title,
      difficulty: sc.difficulty, stepCount: sc.steps.length,
      timestamp: Date.now(),
    };
    pushScenarioHistory(entry);
    setHistory(loadScenarioHistory());
    setCurScenarioId(sc.scenario_id);
    if (resultId) setCurResultId(resultId);
  };

  const loadById = async (sid: string) => {
    setLoading(true); setError("");
    try {
      const sc = await fetchScenario(sid);
      setScenario(sc); setScenarioId(sc.scenario_id);
      saveToHistory(sc);
    } catch (e: unknown) { setError((e as Error).message); }
    finally { setLoading(false); }
  };

  const autoGenerate = async (rid: string) => {
    setLoading(true); setError("");
    try {
      const sc = await generateScenario(rid);
      setScenario(sc); setScenarioId(sc.scenario_id);
      saveToHistory(sc);
      router.replace("/scenario?scenario_id=" + sc.scenario_id);
    } catch (e: unknown) { setError((e as Error).message); }
    finally { setLoading(false); }
  };

  const handleGenerate = () => resultId.trim() && autoGenerate(resultId.trim());
  const handleLoad     = () => scenarioId.trim() && loadById(scenarioId.trim());

  const handleRestoreHistory = (e: ScenarioHistoryEntry) => {
    setScenarioId(e.scenarioId);
    loadById(e.scenarioId);
    setHistOpen(false);
  };

  return (
    <main style={{ padding: "2rem 1.5rem", maxWidth: 900, margin: "0 auto",
      fontFamily: "var(--font-sans)", color: "var(--ink)" }}>

      <div style={{ display: "flex", alignItems: "center",
        justifyContent: "space-between", marginBottom: "1.75rem" }}>
        <div>
          <h1 style={{ color: "var(--ink)", margin: "0 0 0.25rem",
            fontSize: "1.35rem", fontWeight: 600, letterSpacing: "-0.03em" }}>
            Attack Scenario
          </h1>
          <p style={{ color: "var(--ink-subtle)", fontSize: "12px", margin: 0 }}>
            MITRE ATT&amp;CK 기반 공격 시나리오 생성 및 조회
          </p>
        </div>
        <a href="/" className="btn-ghost" style={{ fontSize: "12px" }}>
          &larr; 분석으로
        </a>
      </div>

      {/* 입력 영역 */}
      <div style={{ background: "var(--surface-1)", border: "1px solid var(--hairline)",
        borderRadius: "var(--radius-md)", padding: "1.1rem", marginBottom: "1rem" }}>
        <p style={{ color: "var(--ink-subtle)", fontSize: "12px",
          marginBottom: "0.85rem", lineHeight: 1.6 }}>
          분석 결과 ID로 시나리오 생성, 또는 기존 시나리오 ID로 불러오기
        </p>
        <div style={{ display: "flex", gap: "0.5rem", marginBottom: "0.6rem" }}>
          <input placeholder="result_id (분석 결과 ID → 시나리오 생성)"
            value={resultId} onChange={e => setResultId(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleGenerate()}
            style={{ flex: 1, padding: "0.45rem 0.75rem",
              background: "var(--surface-2)", color: "var(--ink)",
              border: "1px solid var(--hairline-strong)",
              borderRadius: "var(--radius-xs)", fontSize: "13px",
              fontFamily: "var(--font-sans)", outline: "none" }} />
          <button onClick={handleGenerate} disabled={loading || !resultId.trim()}
            className="btn-primary" style={{ fontSize: "12px" }}>생성</button>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <input placeholder="scenario_id (기존 시나리오 불러오기)"
            value={scenarioId} onChange={e => setScenarioId(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleLoad()}
            style={{ flex: 1, padding: "0.45rem 0.75rem",
              background: "var(--surface-2)", color: "var(--ink)",
              border: "1px solid var(--hairline-strong)",
              borderRadius: "var(--radius-xs)", fontSize: "13px",
              fontFamily: "var(--font-sans)", outline: "none" }} />
          <button onClick={handleLoad} disabled={loading || !scenarioId.trim()}
            className="btn-ghost" style={{ fontSize: "12px" }}>불러오기</button>
        </div>
      </div>

      {/* 이력 */}
      {history.length > 0 && (
        <div style={{ border: "1px solid var(--hairline)", borderRadius: "var(--radius-md)",
          background: "var(--surface-1)", marginBottom: "1.25rem", overflow: "hidden" }}>
          <button onClick={() => setHistOpen(v => !v)}
            style={{ width: "100%", display: "flex", alignItems: "center",
              justifyContent: "space-between", padding: "0.6rem 0.85rem",
              background: "none", border: "none", cursor: "pointer",
              color: "var(--ink-subtle)", fontFamily: "var(--font-sans)" }}>
            <span style={{ fontSize: "11px", fontWeight: 600,
              letterSpacing: "0.07em", textTransform: "uppercase" }}>
              Scenario History
              <span style={{ marginLeft: 8, background: "var(--primary-muted)",
                color: "var(--primary-hover)", borderRadius: "var(--radius-full)",
                padding: "1px 7px", fontSize: "10px", fontWeight: 600 }}>
                {history.length}
              </span>
            </span>
            <span style={{ fontSize: "0.72rem", color: "var(--ink-tertiary)" }}>
              {histOpen ? "▲" : "▼"}
            </span>
          </button>
          {histOpen && (
            <div style={{ borderTop: "1px solid var(--hairline)" }}>
              {history.map(e => {
                const dc = DIFF_COLOR[e.difficulty] ?? "#8a8f98";
                const db = DIFF_BG[e.difficulty] ?? "transparent";
                const dd = DIFF_BORDER[e.difficulty] ?? "var(--hairline)";
                return (
                  <div key={e.scenarioId}
                    style={{ display: "flex", alignItems: "center",
                      padding: "0.5rem 0.85rem", borderBottom: "1px solid var(--hairline)",
                      gap: "0.75rem", transition: "background 0.1s" }}
                    onMouseEnter={ev => (ev.currentTarget.style.background = "var(--surface-2)")}
                    onMouseLeave={ev => (ev.currentTarget.style.background = "transparent")}>
                    <button onClick={() => handleRestoreHistory(e)}
                      style={{ flex: 1, display: "flex", alignItems: "center", gap: "0.75rem",
                        background: "none", border: "none", cursor: "pointer", textAlign: "left" }}>
                      <span style={{ fontSize: "10px", fontWeight: 700, color: dc,
                        border: "1px solid " + dd, borderRadius: "var(--radius-xs)",
                        padding: "2px 6px", background: db,
                        minWidth: "5ch", textAlign: "center", letterSpacing: "0.04em" }}>
                        {e.difficulty}
                      </span>
                      <span style={{ color: "var(--ink-muted)", fontSize: "13px",
                        overflow: "hidden", textOverflow: "ellipsis",
                        whiteSpace: "nowrap", maxWidth: 280 }}>
                        {e.title}
                      </span>
                      <span style={{ color: "var(--ink-tertiary)", fontSize: "11px" }}>
                        {e.stepCount}단계
                      </span>
                      <span style={{ marginLeft: "auto", color: "var(--ink-tertiary)",
                        fontSize: "11px", flexShrink: 0 }}>
                        {new Date(e.timestamp).toLocaleDateString("ko-KR",
                          { month: "2-digit", day: "2-digit" })}
                        {" "}
                        {new Date(e.timestamp).toLocaleTimeString("ko-KR",
                          { hour: "2-digit", minute: "2-digit" })}
                      </span>
                    </button>
                    <button onClick={() => {
                        deleteScenarioHistory(e.scenarioId);
                        setHistory(loadScenarioHistory());
                      }}
                      style={{ background: "none", border: "none", cursor: "pointer",
                        color: "var(--ink-tertiary)", fontSize: "0.75rem",
                        padding: "2px 6px", borderRadius: "var(--radius-xs)",
                        transition: "color 0.15s" }}
                      onMouseEnter={ev => (ev.currentTarget.style.color = "#f87171")}
                      onMouseLeave={ev => (ev.currentTarget.style.color = "var(--ink-tertiary)")}>
                      &#x2715;
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* 로딩 */}
      {loading && (
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem",
          padding: "0.75rem 1rem", background: "var(--primary-glow)",
          border: "1px solid rgba(94,106,210,0.25)",
          borderRadius: "var(--radius-md)", marginBottom: "1rem" }}>
          <span style={{ display: "inline-block", width: 14, height: 14,
            borderRadius: "50%", border: "2px solid var(--primary)",
            borderTopColor: "transparent", flexShrink: 0,
            animation: "spin 0.7s linear infinite" }}/>
          <span style={{ color: "var(--primary-hover)", fontSize: "13px" }}>
            시나리오 처리 중 (Claude API 호출)...
          </span>
        </div>
      )}
      {error && (
        <p style={{ color: "#f87171", fontSize: "13px",
          padding: "0.75rem 1rem",
          background: "rgba(248,113,113,0.06)",
          border: "1px solid rgba(248,113,113,0.2)",
          borderRadius: "var(--radius-sm)", marginBottom: "1rem" }}>
          {error}
        </p>
      )}

      {/* 시나리오 결과 */}
      {scenario && (
        <div style={{ background: "var(--surface-1)", border: "1px solid var(--hairline)",
          borderRadius: "var(--radius-md)", padding: "1.25rem" }}
          className="animate-fade-in">
          <div style={{ display: "flex", justifyContent: "space-between",
            alignItems: "flex-start", marginBottom: "0.85rem" }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <h2 style={{ color: "var(--ink)", margin: "0 0 0.3rem",
                fontSize: "1.1rem", fontWeight: 600, letterSpacing: "-0.02em" }}>
                {scenario.title}
              </h2>
              <p style={{ color: "var(--ink-subtle)", margin: 0, fontSize: "13px", lineHeight: 1.6 }}>
                {scenario.description}
              </p>
            </div>
            <span style={{ fontSize: "11px", fontWeight: 700,
              color: DIFF_COLOR[scenario.difficulty] ?? "#8a8f98",
              border: "1px solid " + (DIFF_BORDER[scenario.difficulty] ?? "var(--hairline)"),
              background: DIFF_BG[scenario.difficulty] ?? "transparent",
              borderRadius: "var(--radius-full)", padding: "3px 10px",
              marginLeft: "1rem", flexShrink: 0, letterSpacing: "0.04em" }}>
              {scenario.difficulty}
            </span>
          </div>

          <div style={{ display: "flex", alignItems: "center", gap: "0.75rem",
            marginBottom: "1.25rem", padding: "0.55rem 0.75rem",
            background: "var(--surface-2)", border: "1px solid var(--hairline)",
            borderRadius: "var(--radius-sm)" }}>
            <span style={{ color: "var(--ink-tertiary)", fontSize: "11px" }}>
              ID:{" "}
              <span style={{ fontFamily: "var(--font-mono)",
                color: "var(--primary-hover)", fontSize: "12px" }}>
                {scenario.scenario_id}
              </span>
            </span>
            <a href={"/simulation?scenario_id=" + scenario.scenario_id + (resultId ? "&result_id=" + resultId : "")}
              className="btn-primary" style={{ marginLeft: "auto", fontSize: "12px" }}>
              &#x2192; 시뮬레이션 실행
            </a>
          </div>

          <div style={{ marginBottom: "1.25rem" }}>
            <div className="section-header">
              <span className="section-title">공격 단계 ({scenario.steps.length}단계)</span>
            </div>
            {scenario.steps.map(s => (
              <div key={s.step_number}
                style={{ background: "var(--surface-2)", border: "1px solid var(--hairline)",
                  borderRadius: "var(--radius-sm)", padding: "0.85rem", marginBottom: "0.5rem" }}>
                <div style={{ fontWeight: 600, color: "var(--ink)", marginBottom: "0.3rem",
                  fontSize: "13px", display: "flex", alignItems: "center", gap: "0.5rem" }}>
                  <span style={{ color: "var(--primary)", fontFamily: "var(--font-mono)",
                    fontSize: "11px" }}>#{s.step_number}</span>
                  {s.title}
                  {s.mitre_technique && (
                    <a href={"https://attack.mitre.org/techniques/" + s.mitre_technique.replace(".", "/")}
                      target="_blank" rel="noreferrer"
                      className="badge badge-primary" style={{ textDecoration: "none" }}>
                      {s.mitre_technique}
                    </a>
                  )}
                </div>
                <p style={{ color: "var(--ink-subtle)", margin: "0 0 0.4rem",
                  fontSize: "12px", lineHeight: 1.6 }}>
                  {s.description}
                </p>
                {s.command && (
                  <code style={{ display: "block", background: "var(--surface-3)",
                    border: "1px solid var(--hairline)", padding: "0.4rem 0.65rem",
                    borderRadius: "var(--radius-xs)", color: "#4ade80", fontSize: "12px",
                    fontFamily: "var(--font-mono)" }}>
                    $ {s.command}
                  </code>
                )}
                {s.expected_outcome && (
                  <p style={{ color: "var(--ink-tertiary)", fontSize: "11px",
                    marginTop: "0.35rem", lineHeight: 1.5 }}>
                    예상 결과: {s.expected_outcome}
                  </p>
                )}
              </div>
            ))}
          </div>

          <div>
            <div className="section-header">
              <span className="section-title">방어 수단</span>
            </div>
            <ul style={{ paddingLeft: "1.1rem", margin: 0 }}>
              {scenario.defenses.map((d, i) => (
                <li key={i} style={{ color: "var(--ink-subtle)", fontSize: "13px",
                  marginBottom: "0.3rem", lineHeight: 1.6 }}>
                  {d}
                </li>
              ))}
            </ul>
          </div>

          {scenario.token_usage > 0 && (
            <p style={{ color: "var(--ink-tertiary)", fontSize: "11px",
              marginTop: "1rem", fontFamily: "var(--font-mono)" }}>
              Claude 토큰 사용량: {scenario.token_usage}
            </p>
          )}
        </div>
      )}

      {!loading && !scenario && (
        <div style={{ textAlign: "center", padding: "4rem 2rem", color: "var(--ink-tertiary)" }}>
          <p style={{ fontSize: "13px", lineHeight: 1.7 }}>
            result_id를 입력하고 시나리오를 생성하거나,<br />
            기존 scenario_id로 불러오세요.
          </p>
        </div>
      )}
    </main>
  );
}

export default function ScenarioPage() {
  return (
    <Suspense fallback={
      <main style={{ padding: '2rem 1.5rem', maxWidth: 900, margin: '0 auto',
        fontFamily: 'var(--font-sans)', color: 'var(--ink)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem',
          padding: '0.75rem 1rem', background: 'var(--primary-glow)',
          border: '1px solid rgba(94,106,210,0.25)',
          borderRadius: 'var(--radius-md)', marginTop: '2rem' }}>
          <span style={{ display: 'inline-block', width: 14, height: 14,
            borderRadius: '50%', border: '2px solid var(--primary)',
            borderTopColor: 'transparent', flexShrink: 0,
            animation: 'spin 0.7s linear infinite' }}/>
          <span style={{ color: 'var(--primary-hover)', fontSize: '13px' }}>로딩 중...</span>
        </div>
      </main>
    }>
      <ScenarioContent />
    </Suspense>
  );
}
