"use client";
export const dynamic = "force-dynamic";
import { useState, useEffect, useRef, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import { fetchLabPresets, stopLab, fetchDockerStatus, openLabCreateSSE,
         LabPreset, LabEnvironment, LabProgressEvent } from "@/lib/api";
import {
  loadLabHistory, pushLabHistory, deleteLabHistory, updateLabHistoryStatus,
  LabHistoryEntry, getCurLabId, setCurLabId, getCurPreset, setCurPreset,
} from "@/lib/storage";

const LOG_COLOR: Record<string, string> = {
  complete: "#4ade80", error: "#f87171", pull_start: "var(--primary-hover)",
  pull_done: "#34d399", pull_layer: "var(--ink-tertiary)",
  pull_progress: "var(--ink-tertiary)", status: "var(--ink-muted)", start: "#c084fc",
};

export default function LabPage() {
  const params  = useSearchParams();
  const router  = useRouter();

  const [presets,    setPresets]    = useState<LabPreset[]>([]);
  const [selected,   setSelected]   = useState("");
  const [lab,        setLab]        = useState<LabEnvironment | null>(null);
  const [creating,   setCreating]   = useState(false);
  const [logs,       setLogs]       = useState<LabProgressEvent[]>([]);
  const [error,      setError]      = useState("");
  const [dockerOk,   setDockerOk]   = useState<boolean | null>(null);
  const [dockerMsg,  setDockerMsg]  = useState("");
  const [history,    setHistory]    = useState<LabHistoryEntry[]>([]);
  const [histOpen,   setHistOpen]   = useState(false);
  const logRef  = useRef<HTMLDivElement>(null);
  const closeRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    fetchDockerStatus().then(({ available, reason }) => {
      setDockerOk(available); setDockerMsg(reason);
    });
  }, []);

  useEffect(() => {
    fetchLabPresets().then((p) => {
      setPresets(p);
      const savedPreset = params.get("preset") ?? getCurPreset();
      const found = savedPreset && p.find(x => x.name === savedPreset);
      setSelected(found ? found.name : p.length > 0 ? p[0].name : "");
    }).catch(() => {});
    setHistory(loadLabHistory());
  }, []);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs]);

  const handleCreate = async () => {
    if (!selected || creating) return;
    setCreating(true); setError(""); setLogs([]); setLab(null);
    setCurPreset(selected);

    const close = await openLabCreateSSE(selected, (evt) => {
      setLogs(prev => [...prev, evt]);
      if (evt.event === "complete") {
        const match = evt.message.match(/lab_id=([a-f0-9-]+)/);
        if (match) {
          fetch("http://localhost:8000/labs/" + match[1])
            .then(r => r.json())
            .then((labData: LabEnvironment) => {
              setLab(labData);
              const preset = presets.find(p => p.name === selected);
              const entry: LabHistoryEntry = {
                labId: labData.lab_id,
                presetName: labData.preset_name,
                presetDesc: preset?.description ?? "",
                timestamp: Date.now(),
                status: labData.status,
                targetPorts: labData.target_ports ?? [],
              };
              pushLabHistory(entry);
              setHistory(loadLabHistory());
              setCurLabId(labData.lab_id);
            })
            .catch(() => {});
        }
        setCreating(false);
      }
      if (evt.event === "error") {
        setError(evt.message);
        setCreating(false);
      }
    });
    closeRef.current = close;
  };

  const handleStop = async () => {
    if (!lab) return;
    await stopLab(lab.lab_id);
    setLab(prev => prev ? { ...prev, status: "stopped" } : null);
    updateLabHistoryStatus(lab.lab_id, "stopped");
    setHistory(loadLabHistory());
  };

  const goToSimulation = () => {
    if (!lab) return;
    const sid = params.get("scenario_id") ?? "";
    const url = sid
      ? "/simulation?scenario_id=" + sid + "&lab_id=" + lab.lab_id
      : "/simulation?lab_id=" + lab.lab_id;
    router.push(url);
  };

  const handleRestoreHistory = (e: LabHistoryEntry) => {
    const restored: LabEnvironment = {
      lab_id: e.labId,
      preset_name: e.presetName,
      status: e.status,
      target_ports: e.targetPorts,
      attacker_container_id: null,
      target_container_id: null,
      error: "",
    };
    setLab(restored);
    setCurLabId(e.labId);
    setHistOpen(false);
  };

  const statusColor = (s: string) =>
    s === "running" ? "#4ade80" : s === "error" ? "#f87171" : "var(--ink-subtle)";
  const statusBg = (s: string) =>
    s === "running" ? "rgba(74,222,128,0.07)" : s === "error" ? "rgba(248,113,113,0.07)" : "var(--surface-2)";
  const statusBorder = (s: string) =>
    s === "running" ? "rgba(74,222,128,0.25)" : s === "error" ? "rgba(248,113,113,0.25)" : "var(--hairline)";

  return (
    <main style={{ padding: "2rem 1.5rem", maxWidth: 860, margin: "0 auto",
      fontFamily: "var(--font-sans)", color: "var(--ink)" }}>

      {/* Header */}
      <div style={{ display: "flex", alignItems: "center",
        justifyContent: "space-between", marginBottom: "0.35rem" }}>
        <div>
          <h1 style={{ color: "var(--ink)", margin: "0 0 0.25rem",
            fontSize: "1.35rem", fontWeight: 600, letterSpacing: "-0.03em" }}>
            Docker Lab Manager
          </h1>
          <p style={{ color: "var(--ink-subtle)", fontSize: "12px", margin: 0 }}>
            격리된 공격자 + 대상 컨테이너를 생성해 안전한 시뮬레이션 환경을 구성합니다
          </p>
        </div>
        <a href="/" className="btn-ghost" style={{ fontSize: "12px" }}>
          &larr; 분석으로
        </a>
      </div>

      {/* Docker 상태 배너 */}
      {dockerOk === false && (
        <div style={{ background: "rgba(248,113,113,0.05)",
          border: "1px solid rgba(248,113,113,0.2)",
          borderRadius: "var(--radius-md)",
          padding: "1rem", marginBottom: "1.25rem", marginTop: "1rem" }}>
          <p style={{ color: "#f87171", fontWeight: 600, margin: "0 0 0.35rem", fontSize: "13px" }}>
            Docker Desktop이 실행되지 않고 있습니다
          </p>
          <p style={{ color: "var(--ink-subtle)", margin: "0 0 0.75rem",
            fontSize: "12px", lineHeight: 1.6 }}>
            Docker Desktop을 실행하고 트레이 아이콘이 완전히 뜨면 아래 버튼을 눌러 재확인하세요.
          </p>
          <div style={{ display: "flex", gap: "0.5rem" }}>
            <button onClick={() => fetchDockerStatus().then(({ available, reason }) => {
                setDockerOk(available); setDockerMsg(reason);
              })}
              className="btn-ghost" style={{ fontSize: "12px" }}>
              새로고침
            </button>
            <a href="https://www.docker.com/products/docker-desktop"
              target="_blank" rel="noreferrer" className="btn-ghost"
              style={{ fontSize: "12px", color: "var(--primary-hover)",
                borderColor: "rgba(94,106,210,0.3)" }}>
              Docker Desktop 설치 &rarr;
            </a>
          </div>
        </div>
      )}
      {dockerOk === true && (
        <div style={{ background: "rgba(74,222,128,0.05)",
          border: "1px solid rgba(74,222,128,0.2)", borderRadius: "var(--radius-sm)",
          padding: "0.45rem 0.75rem", marginTop: "0.75rem", marginBottom: "1rem",
          color: "#4ade80", fontSize: "12px", fontWeight: 500 }}>
          ✓ Docker 데몬 연결됨
        </div>
      )}

      {/* 프리셋 선택 */}
      <div style={{ background: "var(--surface-1)", border: "1px solid var(--hairline)",
        borderRadius: "var(--radius-md)", padding: "1.1rem", marginBottom: "1.25rem" }}>
        <div className="section-header">
          <span className="section-title">환경 프리셋</span>
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <select value={selected}
            onChange={(e) => { setSelected(e.target.value); setCurPreset(e.target.value); }}
            disabled={creating}
            style={{ flex: 1, padding: "0.45rem 0.75rem",
              background: "var(--surface-2)", color: "var(--ink)",
              border: "1px solid var(--hairline-strong)", borderRadius: "var(--radius-xs)",
              fontSize: "13px", fontFamily: "var(--font-sans)",
              outline: "none", cursor: "pointer" }}>
            {presets.map((p) => (
              <option key={p.name} value={p.name}>{p.name} — {p.description}</option>
            ))}
          </select>
          <button onClick={handleCreate}
            disabled={creating || !selected || dockerOk === false}
            className={creating ? "btn-ghost" : "btn-primary"}
            style={{ fontSize: "12px", minWidth: "80px" }}>
            {creating ? "생성 중..." : "랩 생성"}
          </button>
        </div>
        {error && (
          <p style={{ color: "#f87171", marginTop: "0.5rem", fontSize: "12px", lineHeight: 1.5 }}>
            {error}
          </p>
        )}
      </div>

      {/* 랩 이력 */}
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
              Lab History
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
              {history.map(e => (
                <div key={e.labId}
                  style={{ display: "flex", alignItems: "center", padding: "0.5rem 0.85rem",
                    borderBottom: "1px solid var(--hairline)", gap: "0.75rem",
                    transition: "background 0.1s" }}
                  onMouseEnter={ev => (ev.currentTarget.style.background = "var(--surface-2)")}
                  onMouseLeave={ev => (ev.currentTarget.style.background = "transparent")}>
                  <button onClick={() => handleRestoreHistory(e)}
                    style={{ flex: 1, display: "flex", alignItems: "center", gap: "0.75rem",
                      background: "none", border: "none", cursor: "pointer", textAlign: "left" }}>
                    <span style={{ fontSize: "10px", fontWeight: 700,
                      color: statusColor(e.status),
                      border: "1px solid " + statusBorder(e.status),
                      background: statusBg(e.status),
                      borderRadius: "var(--radius-xs)", padding: "2px 6px",
                      minWidth: "5.5ch", textAlign: "center", letterSpacing: "0.04em" }}>
                      {e.status}
                    </span>
                    <span style={{ color: "var(--ink-muted)", fontSize: "13px",
                      overflow: "hidden", textOverflow: "ellipsis",
                      whiteSpace: "nowrap", maxWidth: 160 }}>
                      {e.presetName}
                    </span>
                    <span style={{ color: "var(--ink-subtle)", fontSize: "12px",
                      overflow: "hidden", textOverflow: "ellipsis",
                      whiteSpace: "nowrap", maxWidth: 130 }}>
                      {e.presetDesc}
                    </span>
                    <code style={{ color: "var(--ink-tertiary)", fontSize: "11px",
                      marginLeft: "auto", flexShrink: 0, fontFamily: "var(--font-mono)" }}>
                      {e.labId}
                    </code>
                    <span style={{ color: "var(--ink-tertiary)", fontSize: "11px", flexShrink: 0 }}>
                      {new Date(e.timestamp).toLocaleDateString("ko-KR",
                        { month: "2-digit", day: "2-digit" })}
                      {" "}
                      {new Date(e.timestamp).toLocaleTimeString("ko-KR",
                        { hour: "2-digit", minute: "2-digit" })}
                    </span>
                  </button>
                  <a href={"/simulation?lab_id=" + e.labId}
                    className="badge badge-primary"
                    style={{ textDecoration: "none", whiteSpace: "nowrap", flexShrink: 0 }}>
                    시뮬레이션
                  </a>
                  <button onClick={() => { deleteLabHistory(e.labId); setHistory(loadLabHistory()); }}
                    style={{ background: "none", border: "none", cursor: "pointer",
                      color: "var(--ink-tertiary)", fontSize: "0.75rem",
                      padding: "2px 6px", borderRadius: "var(--radius-xs)",
                      transition: "color 0.15s", flexShrink: 0 }}
                    onMouseEnter={ev => (ev.currentTarget.style.color = "#f87171")}
                    onMouseLeave={ev => (ev.currentTarget.style.color = "var(--ink-tertiary)")}>
                    &#x2715;
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* 진행 로그 */}
      {(logs.length > 0 || creating) && (
        <div style={{ background: "var(--canvas)", border: "1px solid var(--hairline)",
          borderRadius: "var(--radius-md)", padding: "0.85rem", marginBottom: "1.25rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between",
            alignItems: "center", marginBottom: "0.5rem" }}>
            <span style={{ color: "var(--ink-muted)", fontSize: "12px",
              fontWeight: 600, letterSpacing: "-0.01em" }}>진행 로그</span>
            {creating && (
              <span style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
                <span style={{ display: "inline-block", width: 10, height: 10,
                  borderRadius: "50%", border: "2px solid #fbbf24",
                  borderTopColor: "transparent",
                  animation: "spin 0.7s linear infinite", flexShrink: 0 }}/>
                <span style={{ color: "#fbbf24", fontSize: "11px" }}>Docker 컨테이너 생성 중...</span>
              </span>
            )}
          </div>
          <div ref={logRef} style={{ maxHeight: 280, overflowY: "auto" }}>
            {logs.map((l, i) => (
              <div key={i} style={{ display: "flex", gap: "0.5rem",
                marginBottom: "0.2rem", fontSize: "12px", fontFamily: "var(--font-mono)" }}>
                <span style={{ color: LOG_COLOR[l.event] ?? "var(--ink-subtle)",
                  minWidth: "12ch", flexShrink: 0 }}>
                  [{l.event}]
                </span>
                <span style={{ color: l.event === "error" ? "#f87171"
                  : l.event === "complete" ? "#4ade80" : "var(--ink-muted)" }}>
                  {l.message}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* 랩 정보 */}
      {lab && (
        <div style={{ background: "var(--surface-1)", border: "1px solid var(--hairline)",
          borderRadius: "var(--radius-md)", padding: "1.25rem" }}
          className="animate-fade-in">
          <div style={{ display: "flex", justifyContent: "space-between",
            alignItems: "center", marginBottom: "1rem" }}>
            <h2 style={{ margin: 0, fontSize: "1rem",
              fontWeight: 600, letterSpacing: "-0.02em" }}>
              Lab{" "}
              <code style={{ fontFamily: "var(--font-mono)",
                color: "var(--primary-hover)", fontSize: "0.9rem" }}>
                {lab.lab_id}
              </code>
            </h2>
            <span style={{ fontSize: "11px", fontWeight: 700,
              color: statusColor(lab.status),
              border: "1px solid " + statusBorder(lab.status),
              background: statusBg(lab.status),
              borderRadius: "var(--radius-full)",
              padding: "3px 10px", letterSpacing: "0.04em" }}>
              {lab.status.toUpperCase()}
            </span>
          </div>

          <table style={{ width: "100%", borderCollapse: "collapse",
            marginBottom: "1rem", fontSize: "13px" }}>
            <tbody>
              {([
                ["프리셋",  lab.preset_name],
                ["공격자",  lab.attacker_container_id ?? "-"],
                ["대상",    lab.target_container_id ?? "-"],
                ["포트",    (lab.target_ports ?? []).join(", ") || "-"],
              ] as [string,string][]).map(([k, v]) => (
                <tr key={k} style={{ borderBottom: "1px solid var(--hairline)" }}>
                  <td style={{ color: "var(--ink-subtle)", padding: "0.45rem 0.5rem",
                    width: "80px" }}>{k}</td>
                  <td style={{ color: "var(--ink)", padding: "0.45rem 0.5rem" }}>
                    <code style={{ fontFamily: "var(--font-mono)", fontSize: "12px" }}>{v}</code>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {lab.error && (
            <p style={{ color: "#f87171", fontSize: "13px", marginBottom: "0.75rem" }}>
              {lab.error}
            </p>
          )}

          {lab.status === "running" ? (
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <button onClick={goToSimulation}
                className="btn-primary" style={{ flex: 1, fontSize: "13px" }}>
                &rarr; 시뮬레이션으로 이동
              </button>
              <button onClick={handleStop} className="btn-ghost"
                style={{ fontSize: "12px", color: "#f87171",
                  borderColor: "rgba(248,113,113,0.3)" }}>
                Stop
              </button>
            </div>
          ) : (
            <div>
              <a href={"/simulation?lab_id=" + lab.lab_id}
                className="btn-ghost"
                style={{ display: "block", textAlign: "center", fontSize: "13px" }}>
                🎮 시뮬레이션 실행 (DRY-RUN 모드)
              </a>
            </div>
          )}
        </div>
      )}
    </main>
  );
}
