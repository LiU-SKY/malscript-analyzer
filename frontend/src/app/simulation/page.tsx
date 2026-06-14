"use client";
export const dynamic = "force-dynamic";
import { useState, useEffect, useRef, useCallback, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import {
  fetchScenario, fetchLabPresets, openSimulationSSE,
  runStep,
  AttackScenario, LabPreset, SimEvent,
  StepResult,
} from "@/lib/api";
import {
  loadSimHistory, pushSimHistory, deleteSimHistory,
  SimHistoryEntry, StoredSimEvent,
  getCurScenarioId, getCurLabId, setCurScenarioId, setCurLabId,
  getCurResultId,
} from "@/lib/storage";

const BASE     = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const WS_BASE  = BASE.replace(/^http/, "ws");

// ── 공격 흐름 다이어그램 ──────────────────────────────────────────────────────
function AttackFlowDiagram({
  steps, stepResults, currentStep,
}: {
  steps: Array<{ step_number: number; title: string; mitre_technique: string; description: string }>;
  stepResults: Record<number, "success" | "failed" | "current" | "skipped">;
  currentStep: number;
}) {
  if (!steps || steps.length === 0) return null;
  const NODE_W = 140, NODE_H = 72, ARROW = 36, PAD_X = 16, PAD_Y = 20;
  const totalW = steps.length * NODE_W + (steps.length - 1) * ARROW + PAD_X * 2;
  const colOf = {
    success: { fill: "#071a0f", stroke: "#22c55e", text: "#4ade80", icon: "✓" },
    failed:  { fill: "#1a0808", stroke: "#ef4444", text: "#f87171", icon: "✗" },
    current: { fill: "#0c1e2f", stroke: "var(--primary)", text: "var(--primary-hover)", icon: "●" },
    skipped: { fill: "var(--surface-1)", stroke: "var(--ink-subtle)", text: "var(--ink-subtle)", icon: "—" },
  } as const;
  type SK = keyof typeof colOf;
  return (
    <div style={{ overflowX: "auto", paddingBottom: 4 }}>
      <svg width={totalW} height={NODE_H + PAD_Y * 2}
        style={{ display: "block", fontFamily: "var(--font-sans)" }} xmlns="http://www.w3.org/2000/svg">
        {steps.map((s, i) => {
          const status = stepResults[s.step_number] as SK | undefined;
          const c = status ? colOf[status] : { fill: "var(--surface-1)", stroke: "var(--hairline-strong)", text: "var(--ink-subtle)", icon: "○" };
          const x = PAD_X + i * (NODE_W + ARROW), y = PAD_Y;
          return (
            <g key={s.step_number}>
              {i < steps.length - 1 && (
                <g>
                  <line x1={x+NODE_W} y1={y+NODE_H/2} x2={x+NODE_W+ARROW-6} y2={y+NODE_H/2}
                    stroke={c.stroke} strokeWidth={1.5} strokeDasharray={status ? "none":"4,3"} opacity={status ? 0.8 : 0.3}/>
                  <polygon
                    points={`${x+NODE_W+ARROW-6},${y+NODE_H/2-4} ${x+NODE_W+ARROW},${y+NODE_H/2} ${x+NODE_W+ARROW-6},${y+NODE_H/2+4}`}
                    fill={status ? c.stroke:"var(--hairline-strong)"} opacity={status ? 0.8:0.3}/>
                </g>
              )}
              {status === "current" && (
                <rect x={x-2} y={y-2} width={NODE_W+4} height={NODE_H+4}
                  rx={8} fill="none" stroke="var(--primary)" strokeWidth={2} opacity={0.35}/>
              )}
              <rect x={x} y={y} width={NODE_W} height={NODE_H} rx={6} fill={c.fill} stroke={c.stroke} strokeWidth={1.5}/>
              <rect x={x+6} y={y+6} width={22} height={16} rx={3} fill={c.stroke} opacity={0.15}/>
              <text x={x+17} y={y+18} fill={c.stroke} fontSize={9} textAnchor="middle" fontWeight="bold">{s.step_number}</text>
              <text x={x+NODE_W-10} y={y+18} fill={c.text} fontSize={10} textAnchor="middle">{c.icon}</text>
              {(() => {
                const title = s.title.length > 18 ? s.title.slice(0,17)+"…" : s.title;
                const words = title.split(" ");
                let l1 = "", l2 = "";
                for (const w of words) {
                  if ((l1 + " " + w).trim().length <= 9) l1 = (l1 + " " + w).trim();
                  else l2 = (l2 + " " + w).trim();
                }
                return <>
                  <text x={x+NODE_W/2} y={y+38} fill={c.text} fontSize={9} textAnchor="middle">{l1}</text>
                  <text x={x+NODE_W/2} y={y+50} fill={c.text} fontSize={9} textAnchor="middle">{l2}</text>
                  <text x={x+NODE_W/2} y={y+63} fill={c.stroke} fontSize={8} textAnchor="middle" opacity={0.7}>{s.mitre_technique}</text>
                </>;
              })()}
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// ── TargetShell — 타깃 컨테이너 인터랙티브 터미널 ─────────────────────────────
type VerifyStatus = "unknown" | "blocked" | "success" | "dry_run" | "infra_error";

type ShellLine =
  | { kind: "input";  text: string }
  | { kind: "output"; text: string; dry: boolean }
  | { kind: "verify"; status: VerifyStatus; reason: string; output: string }
  | { kind: "system"; text: string };

function TargetShell({
  labId, scenarioId, stepNumber, stepMitre, stepTitle,
  onVerifyChange, targetOs,
}: {
  labId: string;
  scenarioId: string;
  stepNumber: number;
  stepMitre: string;
  stepTitle: string;
  onVerifyChange?: (status: VerifyStatus) => void;
  targetOs?: "windows" | "linux" | "unknown";
}) {
  const [lines,         setLines]         = useState<ShellLine[]>([]);
  const [input,         setInput]         = useState("");
  const [connected,     setConnected]     = useState(false);
  const [isDryRun,      setIsDryRun]      = useState(false);
  const [verifyStatus,  setVerifyStatus]  = useState<VerifyStatus>("unknown");
  const [inputHistory,  setInputHistory]  = useState<string[]>([]);
  const [histIdx,       setHistIdx]       = useState(-1);
  const [hintOpen,      setHintOpen]      = useState(false);
  const [verifying,     setVerifying]     = useState(false);

  const wsRef     = useRef<WebSocket | null>(null);
  const termRef   = useRef<HTMLDivElement>(null);
  const inputRef  = useRef<HTMLInputElement>(null);

  // WebSocket 연결 — Linux/Docker 전용 (Windows 타겟은 시뮬레이션 미지원)
  useEffect(() => {
    // Windows 타겟은 시뮬레이션 불가 — 연결하지 않음
    // undefined/unknown/linux → Linux 엔드포인트로 연결 (공격자 셸과 동일 동작)
    if (targetOs === "windows") return;

    const effectiveId = labId || "dry-run";
    // Linux 또는 unknown → Linux Docker 엔드포인트 사용
    const url = `${WS_BASE}/ws/lab/${encodeURIComponent(effectiveId)}/shell/target`;

    // 이전 연결 정리 후 새 연결 시작 (재연결 시 오류 메시지 초기화)
    setLines([]);
    setConnected(false);

    const ws = new WebSocket(url);
    // 페이지 이탈 등 의도적 close 여부 — true면 "연결 끊김" 메시지 억제
    let intentionalClose = false;

    ws.onopen = () => {};
    ws.onclose = () => {
      setConnected(false);
      // 의도적 close(cleanup)가 아닐 때만 끊김 메시지 표시
      if (!intentionalClose) {
        setLines(prev => [...prev, { kind: "system", text: "[연결 끊김 — 백엔드가 실행 중인지 확인하세요]" }]);
      }
    };
    ws.onerror = () => {
      if (!intentionalClose) {
        setLines(prev => [...prev, { kind: "system", text: "[WebSocket 오류 — 백엔드가 실행 중인지 확인하세요]" }]);
      }
    };
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data) as Record<string, unknown>;
        switch (msg.type) {
          case "connected":
            setConnected(true);
            setIsDryRun(!!msg.is_dry_run);
            setLines(prev => [...prev, { kind: "system", text: String(msg.message ?? "[연결됨]") }]);
            break;
          case "status":
            // Windows Sandbox 부팅 상태 메시지 표시
            setLines(prev => [...prev, { kind: "system", text: String(msg.message ?? "") }]);
            break;
          case "output":
            setLines(prev => [...prev, {
              kind: "output",
              text: String(msg.result ?? ""),
              dry: !!msg.is_dry_run,
            }]);
            // 명령 실행 후 자동 검증
            if (scenarioId && stepNumber) {
              setVerifying(true);
              ws.send(JSON.stringify({ type: "verify", scenario_id: scenarioId, step_number: stepNumber }));
            }
            break;
          case "verify_result": {
            const st = String(msg.status ?? "success") as VerifyStatus;
            const reason = String(msg.reason ?? "");
            const out    = String(msg.output ?? "");
            setVerifyStatus(st);
            setVerifying(false);
            setLines(prev => [...prev, { kind: "verify", status: st, reason, output: out }]);
            onVerifyChange?.(st);
            break;
          }
          case "error":
            setLines(prev => [...prev, { kind: "system", text: `[오류] ${msg.message}` }]);
            break;
        }
      } catch { /* ignore parse errors */ }
    };

    wsRef.current = ws;
    return () => { intentionalClose = true; ws.close(); wsRef.current = null; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [labId, targetOs]);

  // 스크롤 아래로
  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [lines]);

  // 단계가 바뀌면 검증 상태 초기화
  useEffect(() => {
    setVerifyStatus("unknown");
    // 새 단계 시작 시 검증 요청
    if (connected && scenarioId && stepNumber && wsRef.current?.readyState === WebSocket.OPEN) {
      setVerifying(true);
      wsRef.current.send(JSON.stringify({ type: "verify", scenario_id: scenarioId, step_number: stepNumber }));
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stepNumber]);

  const sendCommand = () => {
    const cmd = input.trim();
    if (!cmd || !wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    setLines(prev => [...prev, { kind: "input", text: cmd }]);
    setInputHistory(prev => [cmd, ...prev.slice(0, 49)]);
    setHistIdx(-1);
    setInput("");
    wsRef.current.send(JSON.stringify({ type: "run", command: cmd }));
  };

  const requestVerify = () => {
    if (!wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    setVerifying(true);
    wsRef.current.send(JSON.stringify({ type: "verify", scenario_id: scenarioId, step_number: stepNumber }));
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") { e.preventDefault(); sendCommand(); return; }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      const next = Math.min(histIdx + 1, inputHistory.length - 1);
      setHistIdx(next);
      setInput(inputHistory[next] ?? "");
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      const next = Math.max(histIdx - 1, -1);
      setHistIdx(next);
      setInput(next < 0 ? "" : inputHistory[next] ?? "");
    }
  };

  // ── 상태 표시 바 색상 ─────────────────────────────────────────────────────
  const statusInfo: Record<VerifyStatus, { bg: string; border: string; color: string; label: string; icon: string }> = {
    unknown:     { bg: "#0f172a", border: "var(--hairline-strong)", color: "var(--ink-subtle)", label: "검증 대기 중...", icon: "○" },
    blocked:     { bg: "#0a1f0a", border: "#22c55e", color: "#4ade80", label: "공격 차단됨 — 방어 성공!", icon: "🟢" },
    success:     { bg: "#1a0808", border: "#ef4444", color: "#f87171", label: "공격 가능 — 방어 조치 필요", icon: "🔴" },
    dry_run:     { bg: "var(--primary-glow)", border: "var(--primary)", color: "var(--primary-hover)", label: "DRY-RUN 모드 (Docker 미실행)", icon: "〇" },
    infra_error: { bg: "#1a1612", border: "#78716c", color: "#a8a29e", label: "인프라 오류", icon: "⚠" },
  };
  const si = statusInfo[verifyStatus];

  // MITRE 기법별 힌트 명령어
  const hints: Record<string, string[]> = {
    "T1059": ["chmod 000 /usr/bin/bash", "auditctl -a always,exit -F arch=b64 -S execve -k exec_audit", "chmod 000 /usr/bin/curl /usr/bin/wget"],
    "T1059.001": ["chmod 000 /usr/bin/curl /usr/bin/wget", "echo 'export PROMPT_COMMAND=\"history -a\"' >> /etc/bash.bashrc"],
    "T1548": ["sed -i 's/^%sudo.*/%sudo ALL=(ALL:ALL) !ALL/' /etc/sudoers", "find /usr/bin /bin -perm -4000 | xargs -I{} chmod u-s {}"],
    "T1548.002": ["chmod 000 /usr/bin/sudo", "find / -perm -4000 -type f 2>/dev/null | head -20"],
    "T1105": ["iptables -A OUTPUT -p tcp --dport 4444 -j DROP", "chmod 000 /usr/bin/curl /usr/bin/wget /usr/bin/nc"],
    "T1027": ["mount -o remount,noexec /tmp", "grep -rEl '[A-Za-z0-9+/]{100,}' /tmp /home 2>/dev/null"],
    "T1036": ["find /bin /usr/bin -newer /etc/passwd -type f 2>/dev/null", "ps auxf > /var/log/proc_snapshot.txt"],
    "T1574": ["> /etc/ld.so.preload && chattr +i /etc/ld.so.preload", "grep -r 'LD_PRELOAD' /etc /proc/*/environ 2>/dev/null | head -5"],
  };
  const hintCmds = hints[stepMitre] ?? hints[stepMitre?.split(".")?.[0]] ?? [
    "id", "sudo -l", "ls -la /tmp", "ps aux | head -20",
  ];

  return (
    <div style={{ border: "1px solid #1e3a5f", borderRadius: 10, overflow: "hidden",
      background: "var(--canvas)", fontFamily: "var(--font-sans)" }}>

      {/* 헤더 — 연결 상태 + 공격 검증 상태 */}
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "0.55rem 1rem", background: "#070f1a",
        borderBottom: "1px solid var(--hairline)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
          <span style={{ fontSize: "0.8rem", color: "var(--ink-subtle)" }}>
            🐧 TARGET SHELL
          </span>
          {targetOs && targetOs !== "unknown" && targetOs !== "windows" && (
            <span style={{ fontSize: "0.65rem", padding: "1px 6px", borderRadius: 3,
              background: "#0a1f0a",
              border: "1px solid #14532d",
              color: "#4ade80" }}>
              Linux Container
            </span>
          )}
          <span style={{ fontSize: "0.68rem", padding: "1px 7px", borderRadius: 3,
            background: connected ? "#0a1f0a" : "#1a1612",
            border: `1px solid ${connected ? "#14532d" : "#44403c"}`,
            color: connected ? "#4ade80" : "#78716c" }}>
            {connected ? (isDryRun ? "DRY-RUN" : "연결됨") : "연결 중..."}
          </span>
          {stepMitre && (
            <span style={{ fontSize: "0.67rem", color: "#f59e0b",
              border: "1px solid #44310a", borderRadius: 3, padding: "1px 6px" }}>
              {stepMitre}
            </span>
          )}
        </div>
        <button onClick={requestVerify} disabled={!connected || verifying}
          style={{ fontSize: "0.72rem", padding: "3px 10px",
            background: verifying ? "var(--hairline)" : "#0c1e2f",
            color: verifying ? "var(--ink-subtle)" : "var(--primary-hover)",
            border: `1px solid ${verifying ? "var(--hairline-strong)" : "var(--hairline-strong)"}`,
            borderRadius: 4, cursor: verifying ? "not-allowed" : "pointer" }}>
          {verifying ? "검증 중..." : "↺ 공격 재검증"}
        </button>
      </div>

      {/* 공격 차단 상태 배너 */}
      <div style={{ padding: "0.45rem 1rem", background: si.bg,
        borderBottom: `1px solid ${si.border}40`,
        display: "flex", alignItems: "center", gap: "0.5rem" }}>
        <span style={{ fontSize: "0.88rem" }}>{si.icon}</span>
        <span style={{ color: si.color, fontSize: "0.82rem", fontWeight: 600 }}>{si.label}</span>
        {verifyStatus === "blocked" && (
          <span style={{ fontSize: "0.7rem", color: "var(--ink-subtle)", marginLeft: "auto" }}>
            방어 확인 후 "이 공격 단계 실행"으로 검증 가능
          </span>
        )}
      </div>

      {/* 터미널 출력 영역 */}
      <div ref={termRef}
        onClick={() => inputRef.current?.focus()}
        style={{ height: 280, overflowY: "auto", padding: "0.6rem 0.85rem",
          cursor: "text", background: "var(--canvas)" }}>
        {lines.map((l, i) => {
          if (l.kind === "input") return (
            <div key={i} style={{ marginBottom: 2 }}>
              <span style={{ color: "var(--ink-subtle)", userSelect: "none" }}>target:~# </span>
              <span style={{ color: "#fbbf24" }}>{l.text}</span>
            </div>
          );
          if (l.kind === "output") return (
            <pre key={i} style={{ margin: "0 0 4px 0", color: l.dry ? "var(--ink-subtle)" : "var(--ink-subtle)",
              fontSize: "0.78rem", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {l.text || " "}
            </pre>
          );
          if (l.kind === "verify") {
            const vc: Record<VerifyStatus, string> = { unknown: "var(--hairline-strong)", blocked: "#22c55e", success: "#ef4444", dry_run: "var(--primary)", infra_error: "#78716c" };
            const ic: Record<VerifyStatus, string> = { unknown: "○", blocked: "🟢", success: "🔴", dry_run: "〇", infra_error: "⚠" };
            return (
              <div key={i} style={{ marginBottom: 4, padding: "3px 8px",
                borderLeft: `3px solid ${vc[l.status]}40`,
                background: `${vc[l.status]}08` }}>
                <span style={{ color: vc[l.status], fontSize: "0.75rem" }}>
                  {ic[l.status]} [검증] {l.reason || (l.status === "blocked" ? "공격 차단됨" : "공격 가능")}
                </span>
                {l.output && l.status !== "dry_run" && (
                  <pre style={{ margin: "2px 0 0 0", color: "var(--ink-tertiary)",
                    fontSize: "0.68rem", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                    {l.output.slice(0, 200)}{l.output.length > 200 ? "…" : ""}
                  </pre>
                )}
              </div>
            );
          }
          // system
          return (
            <div key={i} style={{ color: "var(--ink-tertiary)", fontSize: "0.72rem", marginBottom: 2,
              fontStyle: "italic" }}>{(l as { kind: "system"; text: string }).text}</div>
          );
        })}
        {/* 커서 깜빡임 */}
        <span style={{ color: "var(--primary)", animation: "blink 1s step-end infinite" }}>▋</span>
      </div>

      {/* 입력 프롬프트 */}
      <div style={{ display: "flex", alignItems: "center",
        borderTop: "1px solid var(--hairline)", padding: "0.4rem 0.85rem",
        background: "#040d18", gap: "0.5rem" }}>
        <span style={{ color: "var(--ink-subtle)", fontSize: "0.82rem",
          userSelect: "none", flexShrink: 0 }}>target:~#</span>
        <input
          ref={inputRef}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={!connected}
          placeholder={connected ? "명령어 입력 후 Enter (↑↓ 이력)" : "연결 대기 중..."}
          style={{ flex: 1, background: "transparent", border: "none", outline: "none",
            color: "#fbbf24", fontSize: "0.82rem", fontFamily: "var(--font-sans)",
            caretColor: "var(--primary)" }}
          autoComplete="off" spellCheck={false}
        />
        <button onClick={sendCommand} disabled={!connected || !input.trim()}
          style={{ padding: "3px 10px", background: connected && input.trim() ? "var(--hairline-strong)" : "var(--hairline)",
            color: connected && input.trim() ? "var(--primary-hover)" : "var(--hairline-strong)",
            border: "1px solid #1e3a5f", borderRadius: 4,
            cursor: connected && input.trim() ? "pointer" : "not-allowed", fontSize: "0.75rem" }}>
          실행
        </button>
      </div>

      {/* MITRE 기법 힌트 (접이식) */}
      <div style={{ borderTop: "1px solid #0d1525" }}>
        <button onClick={() => setHintOpen(v => !v)}
          style={{ width: "100%", display: "flex", alignItems: "center",
            justifyContent: "space-between", padding: "0.4rem 0.85rem",
            background: "none", border: "none", cursor: "pointer",
            color: "var(--ink-tertiary)", fontSize: "0.72rem", fontFamily: "var(--font-sans)" }}>
          <span>💡 {stepMitre} 방어 힌트 명령어</span>
          <span>{hintOpen ? "▲" : "▼"}</span>
        </button>
        {hintOpen && (
          <div style={{ padding: "0.4rem 0.85rem 0.65rem",
            background: "#040d18", borderTop: "1px solid #0d1525" }}>
            {hintCmds.map((cmd, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center",
                gap: "0.5rem", marginBottom: "0.3rem" }}>
                <code style={{ flex: 1, color: "var(--ink-subtle)", fontSize: "0.72rem",
                  background: "#0d1525", padding: "3px 8px", borderRadius: 4,
                  overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                  {cmd}
                </code>
                <button onClick={() => setInput(cmd)}
                  style={{ padding: "2px 8px", fontSize: "0.7rem",
                    background: "var(--surface-2)", color: "var(--primary-hover)",
                    border: "1px solid #1e3a5f", borderRadius: 4, cursor: "pointer",
                    flexShrink: 0 }}>
                  복사
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}


// ── AttackerShell — 공격자(Kali) 컨테이너 인터랙티브 터미널 ─────────────────────
function AttackerShell({ labId }: { labId: string }) {
  const [lines,        setLines]        = useState<ShellLine[]>([]);
  const [input,        setInput]        = useState("");
  const [connected,    setConnected]    = useState(false);
  const [isDryRun,     setIsDryRun]     = useState(false);
  const [inputHistory, setInputHistory] = useState<string[]>([]);
  const [histIdx,      setHistIdx]      = useState(-1);

  const wsRef    = useRef<WebSocket | null>(null);
  const termRef  = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const effectiveId = labId || "dry-run";
    const url = `${WS_BASE}/ws/lab/${encodeURIComponent(effectiveId)}/shell/attacker`;
    const ws = new WebSocket(url);
    // 페이지 이탈 등 의도적 close 여부 — true면 "연결 끊김" 메시지 억제
    let intentionalClose = false;

    ws.onopen  = () => {};
    ws.onclose = () => {
      setConnected(false);
      if (!intentionalClose) {
        setLines(prev => [...prev, { kind: "system", text: "[연결 끊김 — 백엔드가 실행 중인지 확인하세요]" }]);
      }
    };
    ws.onerror = () => {
      if (!intentionalClose) {
        setLines(prev => [...prev, { kind: "system", text: "[WebSocket 오류 — 백엔드가 실행 중인지 확인하세요]" }]);
      }
    };
    ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data) as Record<string, unknown>;
        switch (msg.type) {
          case "connected":
            setConnected(true);
            setIsDryRun(!!msg.is_dry_run);
            setLines(prev => [...prev, { kind: "system", text: String(msg.message ?? "[연결됨]") }]);
            break;
          case "output":
            setLines(prev => [...prev, {
              kind: "output",
              text: String(msg.result ?? ""),
              dry: !!msg.is_dry_run,
            }]);
            break;
          case "error":
            setLines(prev => [...prev, { kind: "system", text: `[오류] ${msg.message}` }]);
            break;
        }
      } catch { /* ignore parse errors */ }
    };

    wsRef.current = ws;
    return () => { intentionalClose = true; ws.close(); wsRef.current = null; };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [labId]);

  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight;
  }, [lines]);

  const sendCommand = () => {
    const cmd = input.trim();
    if (!cmd || !wsRef.current || wsRef.current.readyState !== WebSocket.OPEN) return;
    setLines(prev => [...prev, { kind: "input", text: cmd }]);
    setInputHistory(prev => [cmd, ...prev.slice(0, 49)]);
    setHistIdx(-1);
    setInput("");
    wsRef.current.send(JSON.stringify({ type: "run", command: cmd }));
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") { e.preventDefault(); sendCommand(); return; }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      const next = Math.min(histIdx + 1, inputHistory.length - 1);
      setHistIdx(next); setInput(inputHistory[next] ?? "");
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      const next = Math.max(histIdx - 1, -1);
      setHistIdx(next); setInput(next < 0 ? "" : inputHistory[next] ?? "");
    }
  };

  return (
    <div style={{ border: "1px solid #3b1f1f", borderRadius: 10, overflow: "hidden",
      background: "var(--canvas)", fontFamily: "var(--font-sans)" }}>

      {/* 헤더 */}
      <div style={{ display: "flex", alignItems: "center", gap: "0.6rem",
        padding: "0.55rem 1rem", background: "#130a0a",
        borderBottom: "1px solid var(--hairline)" }}>
        <span style={{ fontSize: "0.8rem", color: "var(--ink-subtle)" }}>🗡 ATTACKER SHELL</span>
        <span style={{ fontSize: "0.68rem", padding: "1px 7px", borderRadius: 3,
          background: connected ? "#1a0808" : "#1a1612",
          border: `1px solid ${connected ? "#7f1d1d" : "#44403c"}`,
          color: connected ? "#fca5a5" : "#78716c" }}>
          {connected ? (isDryRun ? "DRY-RUN" : "연결됨") : "연결 중..."}
        </span>
        <span style={{ marginLeft: "auto", fontSize: "0.67rem", color: "var(--ink-subtle)" }}>
          Kali Linux 공격자 컨테이너
        </span>
      </div>

      {/* 터미널 출력 */}
      <div ref={termRef}
        onClick={() => inputRef.current?.focus()}
        style={{ height: 280, overflowY: "auto", padding: "0.6rem 0.85rem",
          cursor: "text", background: "var(--canvas)" }}>
        {lines.map((l, i) => {
          if (l.kind === "input") return (
            <div key={i} style={{ marginBottom: 2 }}>
              <span style={{ color: "var(--ink-subtle)", userSelect: "none" }}>kali:~# </span>
              <span style={{ color: "#f87171" }}>{l.text}</span>
            </div>
          );
          if (l.kind === "output") return (
            <pre key={i} style={{ margin: "0 0 4px 0", color: l.dry ? "var(--ink-subtle)" : "var(--ink-subtle)",
              fontSize: "0.78rem", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {l.text || " "}
            </pre>
          );
          // system
          return (
            <div key={i} style={{ color: "var(--ink-tertiary)", fontSize: "0.72rem", marginBottom: 2,
              fontStyle: "italic" }}>{(l as { kind: "system"; text: string }).text}</div>
          );
        })}
        <span style={{ color: "#ef4444", animation: "blink 1s step-end infinite" }}>▋</span>
      </div>

      {/* 입력 */}
      <div style={{ display: "flex", alignItems: "center",
        borderTop: "1px solid var(--hairline)", padding: "0.4rem 0.85rem",
        background: "#0d0606", gap: "0.5rem" }}>
        <span style={{ color: "var(--ink-subtle)", fontSize: "0.82rem",
          userSelect: "none", flexShrink: 0 }}>kali:~#</span>
        <input
          ref={inputRef}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={!connected}
          placeholder={connected ? "공격 명령어 입력 후 Enter (↑↓ 이력)" : "연결 대기 중..."}
          style={{ flex: 1, background: "transparent", border: "none", outline: "none",
            color: "#f87171", fontSize: "0.82rem", fontFamily: "var(--font-sans)",
            caretColor: "#ef4444" }}
          autoComplete="off" spellCheck={false}
        />
        <button onClick={sendCommand} disabled={!connected || !input.trim()}
          style={{ padding: "3px 10px",
            background: connected && input.trim() ? "#3b1f1f" : "var(--hairline)",
            color: connected && input.trim() ? "#fca5a5" : "var(--hairline-strong)",
            border: "1px solid #7f1d1d", borderRadius: 4,
            cursor: connected && input.trim() ? "pointer" : "not-allowed", fontSize: "0.75rem" }}>
          실행
        </button>
      </div>
    </div>
  );
}


// ── 수동 모드 단계 카드 ───────────────────────────────────────────────────────
function ManualStepCard({
  step, totalSteps, labId, scenarioId, targetOs,
  onComplete, onSkip,
}: {
  step: AttackScenario["steps"][0];
  totalSteps: number;
  labId: string;
  scenarioId: string;
  targetOs?: "windows" | "linux" | "unknown" | undefined;
  onComplete: (result: StepResult, skipped: boolean) => void;
  onSkip: () => void;
}) {
  const [execLoading,   setExecLoading]   = useState(false);
  const [stepResult,    setStepResult]    = useState<StepResult | null>(null);
  const [verifyStatus,  setVerifyStatus]  = useState<VerifyStatus>("unknown");
  const [activeShell,   setActiveShell]   = useState<"attacker" | "defender">("defender");

  const handleExecute = async () => {
    setExecLoading(true);
    try {
      const result = await runStep(scenarioId, step.step_number, labId || "dry-run");
      setStepResult(result);
    } catch (e) {
      setStepResult({
        step_number: step.step_number, title: step.title,
        mitre_technique: step.mitre_technique, command: step.command,
        exec_command: step.exec_command || "",
        output: `[ERROR] ${e}`, is_dry_run: true,
        defense_blocked: false, defense_keyword: "",
        expected_outcome: step.expected_outcome,
      });
    }
    setExecLoading(false);
  };

  // ── 결과 화면 ────────────────────────────────────────────────────────────
  if (stepResult) {
    const blocked = stepResult.defense_blocked;
    const isDry   = stepResult.is_dry_run;
    const color   = blocked ? "#ef4444" : isDry ? "var(--ink-subtle)" : "#22c55e";
    const label   = blocked ? "⛔ 방어에 차단됨" : isDry ? "〇 DRY-RUN 성공" : "✓ 공격 성공";
    return (
      <div style={{ background: "var(--surface-1)", border: `1px solid ${color}40`,
        borderRadius: 10, overflow: "hidden" }}>
        <div style={{ background: `${color}10`, borderBottom: `1px solid ${color}30`,
          padding: "0.85rem 1.25rem", display: "flex", alignItems: "center",
          justifyContent: "space-between" }}>
          <div>
            <span style={{ color, fontWeight: 700, fontSize: "0.95rem" }}>{label}</span>
            <span style={{ color: "var(--ink-subtle)", fontSize: "0.75rem", marginLeft: "0.75rem" }}>
              단계 {step.step_number}/{totalSteps} — {step.title}
            </span>
          </div>
          {isDry && (
            <span style={{ fontSize: "0.7rem", color: "var(--ink-subtle)",
              border: "1px solid var(--hairline-strong)", borderRadius: 3, padding: "2px 7px" }}>DRY-RUN</span>
          )}
        </div>
        <div style={{ padding: "1rem 1.25rem" }}>
          <div style={{ marginBottom: "0.75rem" }}>
            <p style={{ color: "var(--ink-subtle)", fontSize: "0.7rem", margin: "0 0 0.4rem", letterSpacing: "0.05em" }}>실행 출력</p>
            <pre style={{ background: "var(--canvas)", border: "1px solid var(--hairline)",
              borderRadius: 6, padding: "0.6rem 0.85rem", margin: 0,
              color: "var(--ink-subtle)", fontSize: "0.75rem", overflowX: "auto",
              whiteSpace: "pre-wrap", wordBreak: "break-all", maxHeight: 160, overflowY: "auto" }}>
              {stepResult.output || "(출력 없음)"}
            </pre>
          </div>
          <div style={{ padding: "0.6rem 0.85rem", background: "#0c1a0c",
            border: "1px solid #1a3a1a", borderRadius: 6, marginBottom: "1rem" }}>
            <span style={{ color: "var(--ink-subtle)", fontSize: "0.7rem" }}>예상 결과: </span>
            <span style={{ color: "#86efac", fontSize: "0.8rem" }}>{stepResult.expected_outcome}</span>
          </div>
          <button onClick={() => onComplete(stepResult, false)}
            style={{ width: "100%", padding: "0.65rem", background: "var(--primary)", color: "#fff",
              border: "none", borderRadius: 6, cursor: "pointer", fontSize: "0.88rem",
              fontFamily: "var(--font-sans)" }}>
            {step.step_number >= totalSteps ? "시뮬레이션 완료 ✓" : "다음 단계 ▶"}
          </button>
        </div>
      </div>
    );
  }

  // ── 실행 전 단계 카드 ────────────────────────────────────────────────────
  return (
    <div style={{ background: "var(--surface-1)", border: "1px solid #1e3a5f",
      borderRadius: 10, overflow: "hidden" }}>
      {/* 단계 헤더 */}
      <div style={{ background: "#0a1628", borderBottom: "1px solid var(--hairline)",
        padding: "0.85rem 1.25rem", display: "flex", alignItems: "center",
        justifyContent: "space-between" }}>
        <div>
          <span style={{ color: "var(--primary)", fontWeight: 700, fontSize: "1rem" }}>
            {step.step_number} / {totalSteps}
          </span>
          <span style={{ color: "var(--ink)", fontSize: "0.9rem", marginLeft: "0.75rem" }}>
            {step.title}
          </span>
        </div>
        {step.mitre_technique && (
          <span style={{ fontSize: "0.7rem", color: "#f59e0b",
            border: "1px solid #44310a", borderRadius: 3, padding: "2px 7px" }}>
            {step.mitre_technique}
          </span>
        )}
      </div>

      <div style={{ padding: "1rem 1.25rem" }}>
        {/* 설명 */}
        <p style={{ color: "var(--ink-subtle)", fontSize: "0.82rem", margin: "0 0 1rem", lineHeight: 1.7 }}>
          {step.description}
        </p>

        {/* 공격 명령어 */}
        <div style={{ marginBottom: "0.6rem" }}>
          <p style={{ color: "var(--ink-subtle)", fontSize: "0.7rem", margin: "0 0 0.35rem", letterSpacing: "0.05em" }}>
            원본 공격 명령어
          </p>
          <code style={{ display: "block", background: "var(--canvas)",
            border: "1px solid var(--hairline)", borderRadius: 6,
            padding: "0.5rem 0.75rem", color: "#fbbf24",
            fontSize: "0.75rem", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
            {step.command || "(없음)"}
          </code>
        </div>
        {step.exec_command && step.exec_command !== step.command && (
          <div style={{ marginBottom: "1rem" }}>
            <p style={{ color: "var(--ink-subtle)", fontSize: "0.7rem", margin: "0 0 0.35rem", letterSpacing: "0.05em" }}>
              실행 명령어 (Linux/Kali)
            </p>
            <code style={{ display: "block", background: "var(--canvas)",
              border: "1px solid var(--hairline)", borderRadius: 6,
              padding: "0.5rem 0.75rem", color: "var(--primary)",
              fontSize: "0.75rem", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
              {step.exec_command}
            </code>
          </div>
        )}

        {/* 셸 탭 스위처 */}
        <div style={{ marginBottom: "1rem" }}>
          {/* 탭 헤더 */}
          <div style={{ display: "flex", gap: "2px", marginBottom: "0.5rem",
            background: "var(--surface-1)", borderRadius: 7, padding: "3px",
            border: "1px solid var(--hairline)" }}>
            {(["defender", "attacker"] as const).map(tab => {
              const isActive = activeShell === tab;
              const label = tab === "defender" ? "🛡 방어자 셸" : "🗡 공격자 셸";
              const activeColor = tab === "defender" ? "var(--primary)" : "#f87171";
              return (
                <button key={tab} onClick={() => setActiveShell(tab)}
                  style={{ flex: 1, padding: "0.4rem 0", border: "none", borderRadius: 5,
                    cursor: "pointer", fontFamily: "var(--font-sans)", fontSize: "0.78rem",
                    fontWeight: isActive ? 700 : 400, transition: "all 0.15s",
                    background: isActive
                      ? (tab === "defender" ? "#0c1e2f" : "#1a0808")
                      : "transparent",
                    color: isActive ? activeColor : "var(--ink-subtle)",
                    boxShadow: isActive ? `0 0 0 1px ${activeColor}40` : "none" }}>
                  {label}
                  {tab === "defender" && verifyStatus !== "unknown" && (
                    <span style={{ marginLeft: 6, fontSize: "0.65rem",
                      verticalAlign: "middle" }}>
                      {verifyStatus === "blocked" ? "🟢" : verifyStatus === "success" ? "🔴" : ""}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
          {/* 탭 패널 */}
          <div style={{ display: activeShell === "defender" ? "block" : "none" }}>
            <TargetShell
              labId={labId}
              scenarioId={scenarioId}
              stepNumber={step.step_number}
              stepMitre={step.mitre_technique}
              stepTitle={step.title}
              onVerifyChange={setVerifyStatus}
              targetOs={targetOs}
            />
          </div>
          <div style={{ display: activeShell === "attacker" ? "block" : "none" }}>
            <AttackerShell labId={labId} />
          </div>
          {!labId && (
            <p style={{ fontSize: "0.65rem", color: "var(--ink-subtle)", margin: "0.35rem 0 0",
              textAlign: "right" }}>
              ※ Docker 랩 미실행 — DRY-RUN 모드
            </p>
          )}
        </div>

        {/* 실행 / 건너뜀 버튼 */}
        <div style={{ display: "flex", gap: "0.75rem",
          borderTop: "1px solid var(--hairline)", paddingTop: "0.85rem" }}>
          <button onClick={handleExecute} disabled={execLoading}
            style={{ flex: 1, padding: "0.65rem", fontSize: "0.9rem",
              background: execLoading ? "var(--hairline)"
                : verifyStatus === "blocked" ? "#1a0808"
                : "#7f1d1d",
              color: execLoading ? "var(--ink-subtle)"
                : verifyStatus === "blocked" ? "#fca5a5"
                : "#fca5a5",
              border: `1px solid ${execLoading ? "var(--hairline-strong)" : verifyStatus === "blocked" ? "#991b1b" : "#991b1b"}`,
              borderRadius: 6, cursor: execLoading ? "not-allowed" : "pointer",
              fontFamily: "var(--font-sans)", fontWeight: 700, position: "relative" }}>
            {execLoading ? "⏳ 공격 실행 중..." : "▶ 이 공격 단계 실행"}
            {verifyStatus === "blocked" && !execLoading && (
              <span style={{ position: "absolute", top: -8, right: 8,
                fontSize: "0.62rem", background: "#22c55e", color: "#fff",
                borderRadius: 6, padding: "1px 5px" }}>방어됨 — 돌파 시도</span>
            )}
          </button>
          <button onClick={() => onSkip()} disabled={execLoading}
            style={{ padding: "0.65rem 1.1rem", fontSize: "0.82rem",
              background: "none", color: "var(--ink-subtle)",
              border: "1px solid var(--hairline-strong)", borderRadius: 6,
              cursor: execLoading ? "not-allowed" : "pointer",
              fontFamily: "var(--font-sans)" }}>
            건너뜀
          </button>
        </div>
      </div>
    </div>
  );
}

// ── 메인 페이지 ───────────────────────────────────────────────────────────────
function SimulationContent() {
  const params = useSearchParams();

  const [scenarioId,  setScenarioId]  = useState(params.get("scenario_id") ?? "");
  const [scenario,    setScenario]    = useState<AttackScenario | null>(null);
  const [labId,       setLabId]       = useState(params.get("lab_id") ?? "");
  const [presets,     setPresets]     = useState<LabPreset[]>([]);
  const [error,       setError]       = useState("");
  const [history,     setHistory]     = useState<SimHistoryEntry[]>([]);
  const [histOpen,    setHistOpen]    = useState(false);
  const [viewingHistory, setViewingHistory] = useState<SimHistoryEntry | null>(null);
  const [resultId,     setResultId]   = useState(params.get("result_id") ?? "");
  const [targetOs,     setTargetOs]   = useState<"windows" | "linux" | "unknown" | undefined>(undefined);
  const [osConfidence, setOsConfidence] = useState<"high" | "medium" | "low">("low");
  const [osReason,     setOsReason]   = useState("");
  const [reportLoading,    setReportLoading]    = useState(false);
  const [scenarioLoading,  setScenarioLoading]  = useState(false);
  const [vizTab,  setVizTab]  = useState<"flow"|"log">("flow");

  const [simMode, setSimMode] = useState<"auto"|"manual">("manual");

  // 자동 모드
  const [events,      setEvents]      = useState<SimEvent[]>([]);
  const [running,     setRunning]     = useState(false);
  const [done,        setDone]        = useState(false);
  const [currentStep, setCurrentStep] = useState(0);
  const [totalSteps,  setTotalSteps]  = useState(0);
  const [stepResults, setStepResults] = useState<Record<number, "success"|"failed"|"current"|"skipped">>({});
  const [backendSimId, setBackendSimId] = useState("");

  // 수동 모드
  const [manualStep,    setManualStep]    = useState(0);
  const [manualResults, setManualResults] = useState<Record<number, "success"|"failed"|"current"|"skipped">>({});
  const [manualDone,    setManualDone]    = useState(false);
  const [manualSucc,    setManualSucc]    = useState(0);
  const [manualFail,    setManualFail]    = useState(0);

  const logRef   = useRef<HTMLDivElement>(null);
  const closeRef = useRef<(() => void) | null>(null);

  useEffect(() => { fetchLabPresets().then(setPresets).catch(() => {}); }, []);

  // result_id로 OS 정보 로드
  useEffect(() => {
    const rid = params.get("result_id") || resultId;
    if (!rid) return;
    fetch(`${BASE}/analyze/${rid}`)
      .then(r => r.json())
      .then((data: { success: boolean; result?: { target_os?: string; os_confidence?: string; os_reason?: string } }) => {
        if (data.success && data.result) {
          const os = (data.result.target_os ?? "unknown") as "windows" | "linux" | "unknown";
          const conf = (data.result.os_confidence ?? "low") as "high" | "medium" | "low";
          setTargetOs(os);
          setOsConfidence(conf);
          setOsReason(data.result.os_reason ?? "");
        }
      })
      .catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [resultId]);

  useEffect(() => {
    setHistory(loadSimHistory());
    const finalSid = params.get("scenario_id") || getCurScenarioId();
    const finalLid = params.get("lab_id") || getCurLabId();
    const savedRid = params.get("result_id") || getCurResultId();
    if (savedRid) setResultId(savedRid);
    if (finalSid && finalSid !== scenarioId) setScenarioId(finalSid);
    if (finalLid && finalLid !== labId) setLabId(finalLid);
    if (finalSid) {
      fetchScenario(finalSid)
        .then(s => { setScenario(s); setTotalSteps(s.steps.length); })
        .catch((e: unknown) => {
          setError(`시나리오 로드 실패: ${(e as Error).message}`);
        });
    }
  }, []);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [events]);

  const loadScenario = async () => {
    if (!scenarioId.trim()) return;
    setError(""); setScenario(null); setScenarioLoading(true);
    try {
      const s = await fetchScenario(scenarioId.trim());
      setScenario(s); setTotalSteps(s.steps.length);
      setCurScenarioId(s.scenario_id);
    } catch (e: unknown) { setError((e as Error).message); }
    finally { setScenarioLoading(false); }
  };

  const downloadReport = async () => {
    // result_id가 URL에 없을 경우 storage 폴백 (scenario → simulation 직접 링크 경로 대응)
    const rid = resultId || getCurResultId();
    if (!rid) { alert("분석 결과 ID(result_id)가 없습니다.\n분석 탭에서 스크립트를 먼저 분석하세요."); return; }
    if (!resultId) setResultId(rid);   // 상태 동기화
    setReportLoading(true);
    try {
      const p = new URLSearchParams({ result_id: rid });
      if (scenario?.scenario_id) p.set("scenario_id", scenario.scenario_id);
      if (backendSimId) p.set("sim_id", backendSimId);
      const res = await fetch(`${BASE}/reports/generate?${p}`);
      if (!res.ok) { alert("보고서 생성 실패: " + await res.text()); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a"); a.href = url;
      a.download = `report_${scenario?.title ?? rid}.pdf`; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { alert("오류: " + e); }
    finally { setReportLoading(false); }
  };

  // 자동 모드 실행
  const runAutoSim = () => {
    if (!scenario) { setError("시나리오를 먼저 로드하세요."); return; }
    setEvents([]); setRunning(true); setDone(false);
    setError(""); setCurrentStep(0); setStepResults({});
    setViewingHistory(null);
    const allEvents: SimEvent[] = [];
    const finalResults: Record<number, "success"|"failed"|"current"> = {};
    const close = openSimulationSSE(scenario.scenario_id, (ev) => {
      allEvents.push(ev); setEvents(prev => [...prev, ev]);
      if (ev.event_type === "step_start") {
        setCurrentStep(ev.step);
        setStepResults(prev => ({ ...prev, [ev.step]: "current" }));
        finalResults[ev.step] = "current";
      }
      if (ev.event_type === "step_done") {
        setStepResults(prev => ({ ...prev, [ev.step]: "success" }));
        finalResults[ev.step] = "success";
      }
      if (ev.event_type === "step_failed") {
        setStepResults(prev => ({ ...prev, [ev.step]: "failed" }));
        finalResults[ev.step] = "failed";
      }
      if (ev.event_type === "complete") {
        setRunning(false); setDone(true);
        setCurrentStep(scenario.steps.length);
        const m = (ev.detail ?? "").match(/sim_id=([a-f0-9-]+)/);
        if (m) setBackendSimId(m[1]);
        close();
        const sc = Object.values(finalResults).filter(v => v === "success").length;
        const fc = Object.values(finalResults).filter(v => v === "failed").length;
        pushSimHistory({
          simId: `sim-${Date.now().toString(36)}`,
          scenarioId: scenario.scenario_id, scenarioTitle: scenario.title,
          labId: labId || "dry-run", timestamp: Date.now(),
          totalSteps: scenario.steps.length, successCount: sc, failedCount: fc,
          events: allEvents.map(e => ({
            event_type: e.event_type, step: e.step, message: e.message, detail: e.detail ?? "",
          })),
        });
        setHistory(loadSimHistory());
      }
      if (ev.event_type === "error") { setRunning(false); setError(ev.message ?? "오류"); close(); }
    }, labId || undefined);
    closeRef.current = close;
  };

  // 수동 모드 핸들러
  const startManual = () => {
    if (!scenario) return;
    setManualStep(1); setManualResults({}); setManualDone(false);
    setManualSucc(0); setManualFail(0); setViewingHistory(null);
    setTotalSteps(scenario.steps.length);
    setManualResults(prev => ({ ...prev, [1]: "current" }));
  };

  const resetManual = () => {
    setManualStep(0); setManualResults({}); setManualDone(false);
    setManualSucc(0); setManualFail(0);
  };

  const handleManualStepComplete = useCallback((result: StepResult, skipped: boolean) => {
    if (!scenario) return;
    const n = result.step_number;
    const outcome = skipped ? "skipped" : result.defense_blocked ? "failed" : "success";
    setManualResults(prev => ({ ...prev, [n]: outcome }));
    if (!skipped) {
      if (result.defense_blocked) setManualFail(f => f + 1);
      else setManualSucc(s => s + 1);
    }
    const nextN = n + 1;
    if (nextN > scenario.steps.length) {
      setManualDone(true); setManualStep(scenario.steps.length + 1);
      pushSimHistory({
        simId: `sim-${Date.now().toString(36)}`,
        scenarioId: scenario.scenario_id, scenarioTitle: scenario.title,
        labId: labId || "dry-run", timestamp: Date.now(),
        totalSteps: scenario.steps.length,
        successCount: manualSucc + (!skipped && !result.defense_blocked ? 1 : 0),
        failedCount: manualFail + (!skipped && result.defense_blocked ? 1 : 0),
        events: [],
      });
      setHistory(loadSimHistory());
    } else {
      setManualStep(nextN);
      setManualResults(prev => ({ ...prev, [nextN]: "current" }));
    }
  }, [scenario, labId, manualSucc, manualFail]);

  const handleManualSkip = useCallback(() => {
    if (!scenario) return;
    const n = manualStep;
    setManualResults(prev => ({ ...prev, [n]: "skipped" }));
    const nextN = n + 1;
    if (nextN > scenario.steps.length) {
      setManualDone(true); setManualStep(scenario.steps.length + 1);
    } else {
      setManualStep(nextN);
      setManualResults(prev => ({ ...prev, [nextN]: "current" }));
    }
  }, [scenario, manualStep]);

  // 이력 복원
  const handleRestoreHistory = (e: SimHistoryEntry) => {
    setViewingHistory(e); setHistOpen(false);
    const restored: Record<number, "success"|"failed"|"current"|"skipped"> = {};
    e.events.forEach(ev => {
      if (ev.event_type === "step_done")   restored[ev.step] = "success";
      if (ev.event_type === "step_failed") restored[ev.step] = "failed";
    });
    setStepResults(restored); setTotalSteps(e.totalSteps);
    setCurrentStep(e.totalSteps); setDone(false); setRunning(false); setEvents([]);
    if (e.scenarioId !== scenario?.scenario_id) {
      setScenarioId(e.scenarioId);
      fetchScenario(e.scenarioId).then(s => { setScenario(s); setTotalSteps(s.steps.length); }).catch(() => {});
    }
    if (e.labId !== "dry-run") setLabId(e.labId);
  };

  type EvStyle = { border: string; color: string; bg: string; label: string };
  const evStyle = (t: string): EvStyle => {
    const m: Record<string, EvStyle> = {
      step_start:        { border: "var(--primary)", color: "var(--primary)", bg: "var(--primary-glow)",  label: "시작"    },
      step_done:         { border: "#22c55e", color: "#4ade80", bg: "#071a0f",  label: "성공 ✓"  },
      step_failed:       { border: "#ef4444", color: "#f87171", bg: "#1a0808",  label: "실패 ✗"  },
      step_error:        { border: "#78716c", color: "#a8a29e", bg: "#1a1612",  label: "환경오류" },
      defense_triggered: { border: "#f97316", color: "#fb923c", bg: "#1c1008",  label: "방어!"   },
      log:               { border: "var(--hairline)", color: "var(--ink-subtle)", bg: "transparent", label: ""    },
      complete:          { border: "#a78bfa", color: "#a78bfa", bg: "#12082a",  label: "완료"    },
      error:             { border: "#ef4444", color: "#f87171", bg: "#1a0808",  label: "오류"    },
    };
    return m[t] ?? { border: "var(--hairline)", color: "var(--ink-subtle)", bg: "transparent", label: t };
  };

  const autoSucc = Object.values(stepResults).filter(v => v === "success").length;
  const autoFail = Object.values(stepResults).filter(v => v === "failed").length;
  const pct = totalSteps > 0 ? Math.round((currentStep / totalSteps) * 100) : 0;
  const displayEvents: (SimEvent | StoredSimEvent)[] = viewingHistory ? viewingHistory.events : events;
  const showProgress = running || done || !!viewingHistory || manualDone || manualStep > 0;
  const activeResults = simMode === "manual" ? manualResults : stepResults;
  const activeSucc = simMode === "manual" ? manualSucc : autoSucc;
  const activeFail = simMode === "manual" ? manualFail : autoFail;
  const currentManualStepObj = scenario?.steps.find(s => s.step_number === manualStep);

  return (
    <main style={{ padding: "2rem", maxWidth: 960, margin: "0 auto",
      fontFamily: "var(--font-sans)", color: "var(--ink)" }}>

      {/* 헤더 */}
      <div style={{ display: "flex", alignItems: "center",
        justifyContent: "space-between", marginBottom: "1.5rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
          <h1 style={{ color: "var(--ink)", margin: 0, fontSize: "1.4rem", fontWeight: 600, letterSpacing: "-0.02em" }}>Attack Simulation</h1>
          {targetOs && targetOs !== "unknown" && (
            <span title={osReason} style={{
              fontSize: "0.72rem", padding: "2px 9px", borderRadius: 4,
              background: targetOs === "windows" ? "#0d1a2d" : "#0a1f0a",
              border: `1px solid ${targetOs === "windows" ? "#1e4080" : "#14532d"}`,
              color: targetOs === "windows" ? "#60a5fa" : "#4ade80",
              cursor: "help",
            }}>
              {targetOs === "windows" ? "🪟 Windows 타겟" : "🐧 Linux 타겟"}
              {osConfidence === "high" && " ●"}
            </span>
          )}
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          {scenario && (
            <a href={"/scenario?scenario_id=" + scenario.scenario_id}
              style={{ color: "var(--ink-subtle)", fontSize: "0.8rem", textDecoration: "none",
                border: "1px solid var(--hairline)", padding: "0.3rem 0.75rem", borderRadius: 4 }}>
              ← 시나리오
            </a>
          )}
          <a href="/" style={{ color: "var(--ink-subtle)", fontSize: "0.8rem", textDecoration: "none",
            border: "1px solid var(--hairline)", padding: "0.3rem 0.75rem", borderRadius: 4 }}>
            분석으로
          </a>
        </div>
      </div>

      {/* 설정 패널 */}
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "1rem", marginBottom: "1.25rem" }}>
        <div style={{ background: "var(--surface-1)", border: "1px solid var(--hairline)", borderRadius: 8, padding: "1.25rem" }}>
          <h3 style={{ color: "var(--primary-hover)", margin: "0 0 0.75rem", fontSize: "0.82rem", letterSpacing: "0.06em" }}>SCENARIO</h3>
          {scenario ? (
            <div>
              <p style={{ color: "#4ade80", margin: "0 0 0.2rem", fontSize: "0.88rem" }}>✓ {scenario.title}</p>
              <p style={{ color: "var(--ink-subtle)", margin: "0 0 0.2rem", fontSize: "0.75rem" }}>{scenario.steps.length}단계 · {scenario.difficulty}</p>
              <p style={{ color: "var(--ink-tertiary)", margin: "0 0 0.5rem", fontSize: "0.7rem" }}>ID: {scenario.scenario_id}</p>
              <button onClick={() => { setScenario(null); setScenarioId(""); setEvents([]); setStepResults({}); setViewingHistory(null); resetManual(); }}
                style={{ fontSize: "0.75rem", color: "var(--ink-subtle)", background: "none",
                  border: "1px solid var(--hairline-strong)", borderRadius: 4, padding: "0.2rem 0.5rem", cursor: "pointer" }}>변경</button>
            </div>
          ) : (
            <div style={{ display: "flex", gap: "0.5rem" }}>
              <input placeholder="scenario_id" value={scenarioId}
                onChange={e => setScenarioId(e.target.value)}
                onKeyDown={e => e.key === "Enter" && loadScenario()}
                style={{ flex: 1, padding: "0.4rem", background: "var(--surface-2)",
                  color: "var(--ink)", border: "1px solid var(--hairline-strong)", borderRadius: 4, fontSize: "0.82rem" }}/>
              <button onClick={loadScenario} disabled={!scenarioId.trim()}
                style={{ padding: "0.4rem 0.75rem", background: "var(--primary)", color: "#fff",
                  border: "none", borderRadius: 4, cursor: "pointer" }}>로드</button>
            </div>
          )}
        </div>
        <div style={{ background: "var(--surface-1)", border: "1px solid var(--hairline)", borderRadius: 8, padding: "1.25rem" }}>
          <h3 style={{ color: "var(--primary-hover)", margin: "0 0 0.75rem", fontSize: "0.82rem", letterSpacing: "0.06em" }}>DOCKER LAB (선택)</h3>
          {labId ? (
            <div>
              <p style={{ color: "#4ade80", margin: "0 0 0.2rem", fontSize: "0.88rem" }}>✓ 랩 연결됨</p>
              <p style={{ color: "var(--primary-hover)", margin: "0 0 0.5rem", fontSize: "0.75rem" }}>{labId}</p>
              <button onClick={() => setLabId("")}
                style={{ fontSize: "0.75rem", color: "var(--ink-subtle)", background: "none",
                  border: "1px solid var(--hairline-strong)", borderRadius: 4, padding: "0.2rem 0.5rem", cursor: "pointer" }}>연결 해제</button>
            </div>
          ) : (
            <div>
              <input placeholder="lab_id (비우면 DRY-RUN)" value={labId}
                onChange={e => setLabId(e.target.value)}
                style={{ width: "100%", padding: "0.4rem", background: "var(--surface-2)",
                  color: "var(--ink)", border: "1px solid var(--hairline-strong)", borderRadius: 4,
                  fontSize: "0.78rem", boxSizing: "border-box", marginBottom: "0.35rem" }}/>
              <p style={{ color: "var(--ink-subtle)", fontSize: "0.7rem", margin: 0 }}>비워두면 DRY-RUN으로 실행</p>
            </div>
          )}
        </div>
      </div>

      {/* 시나리오 로딩 스피너 */}
      {scenarioLoading && (
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem",
          padding: "0.85rem 1.25rem", background: "var(--primary-glow)",
          border: "1px solid #1e3a5f", borderRadius: 8, marginBottom: "1.25rem" }}>
          <span style={{ display: "inline-block", width: 14, height: 14,
            borderRadius: "50%", border: "2px solid var(--primary)",
            borderTopColor: "transparent", flexShrink: 0,
            animation: "spin 0.7s linear infinite" }}/>
          <span style={{ color: "var(--primary-hover)", fontSize: "13px" }}>시나리오 불러오는 중...</span>
        </div>
      )}

      {error && (
        <div style={{ color: "#f87171", background: "#1a0808", padding: "0.6rem 1rem",
          borderRadius: 6, marginBottom: "1rem", border: "1px solid #7f1d1d", fontSize: "0.85rem" }}>
          ⚠ {error}
        </div>
      )}

      {/* 자동 모드 실행 버튼 */}
      {simMode === "auto" && !viewingHistory && (
        <div style={{ display: "flex", gap: "0.75rem", marginBottom: "1.25rem" }}>
          <button onClick={runAutoSim} disabled={running || !scenario}
            style={{ flex: 1, padding: "0.7rem",
              background: running ? "#1e293b" : "#0ea5e9",
              color: running ? "#475569" : "#fff",
              border: "none", borderRadius: 8, fontSize: "0.95rem",
              cursor: running || !scenario ? "not-allowed" : "pointer", fontFamily: "monospace" }}>
            {running ? "● 시뮬레이션 실행 중..." : done ? "↺ 다시 실행" : "▶ 시뮬레이션 자동 시작"}
          </button>
          {running && (
            <button onClick={() => { closeRef.current?.(); setRunning(false); }}
              style={{ padding: "0.7rem 1.2rem", background: "#7f1d1d", color: "#fca5a5",
                border: "none", borderRadius: 8, cursor: "pointer", fontFamily: "monospace" }}>
              ■ 중단
            </button>
          )}
        </div>
      )}

      {/* 수동 모드 시작 버튼 */}
      {simMode === "manual" && !viewingHistory && manualStep === 0 && (
        <button onClick={startManual} disabled={!scenario}
          style={{ width: "100%", padding: "0.85rem", marginBottom: "1.25rem",
            background: !scenario ? "#1e293b" : "#1c2a1c",
            color: !scenario ? "#475569" : "#4ade80",
            border: `1px solid ${!scenario ? "#334155" : "#166534"}`,
            borderRadius: 8, fontSize: "0.95rem",
            cursor: !scenario ? "not-allowed" : "pointer", fontFamily: "monospace" }}>
          🎮 수동 시뮬레이션 시작 — 타깃 셸에서 직접 방어 후 공격 실행
        </button>
      )}

      {/* 수동 완료 화면 */}
      {simMode === "manual" && manualDone && !viewingHistory && (
        <div style={{ background: activeFail > 0 ? "#1a0f08" : "#0d1a0d",
          border: `1px solid ${activeFail > 0 ? "#7c2d12" : "#14532d"}`,
          borderRadius: 10, padding: "1.5rem", marginBottom: "1.25rem", textAlign: "center" }}>
          <p style={{ color: activeFail > 0 ? "#fb923c" : "#4ade80",
            fontSize: "1.1rem", margin: "0 0 0.5rem", fontWeight: 700 }}>
            {activeFail > 0
              ? `⚠ 시뮬레이션 완료 — ${activeSucc}단계 공격 성공 / ${activeFail}단계 방어에 차단`
              : `✓ 시뮬레이션 완료 — ${totalSteps}단계 전부 성공`}
          </p>
          <button onClick={resetManual}
            style={{ padding: "0.6rem 2rem", background: "#1e293b", color: "#7dd3fc",
              border: "1px solid #1e3a5f", borderRadius: 6, cursor: "pointer", fontFamily: "monospace" }}>
            ↺ 다시 시작
          </button>
        </div>
      )}

      {/* 공격 흐름 다이어그램 */}
      {scenario && (showProgress || manualStep > 0) && (
        <div style={{ marginBottom: "1.25rem" }}>
          <div style={{ display: "flex", gap: "0.25rem", marginBottom: "0.6rem",
            alignItems: "center", justifyContent: "space-between" }}>
            <div style={{ display: "flex", gap: "0.25rem" }}>
              {(["flow","log"] as const).map(t => (
                <button key={t} onClick={() => setVizTab(t)}
                  style={{ padding: "0.3rem 0.85rem", fontSize: "0.75rem",
                    border: `1px solid ${vizTab === t ? "#0ea5e9" : "#1e293b"}`,
                    background: vizTab === t ? "#0c1e2f" : "transparent",
                    color: vizTab === t ? "#7dd3fc" : "#475569",
                    borderRadius: 4, cursor: "pointer", fontFamily: "monospace" }}>
                  {t === "flow" ? "흐름도" : "이벤트 로그"}
                </button>
              ))}
            </div>
            {(done || manualDone || !!viewingHistory) && (
              <button onClick={downloadReport} disabled={reportLoading}
                style={{ padding: "0.3rem 0.9rem", fontSize: "0.78rem",
                  background: reportLoading ? "#1e293b" : "#0f3a2a",
                  color: reportLoading ? "#475569" : "#4ade80",
                  border: `1px solid ${reportLoading ? "#334155" : "#22c55e60"}`,
                  borderRadius: 4, cursor: reportLoading ? "not-allowed" : "pointer", fontFamily: "monospace" }}>
                {reportLoading ? "⏳ 생성 중..." : "📄 PDF 보고서"}
              </button>
            )}
          </div>

          {/* 진행 바 */}
          <div style={{ marginBottom: "0.75rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between",
              fontSize: "0.78rem", color: "#475569", marginBottom: "0.35rem" }}>
              <span>
                {viewingHistory
                  ? `이력 — 성공 ${viewingHistory.successCount} / 실패 ${viewingHistory.failedCount} / 전체 ${viewingHistory.totalSteps}`
                  : simMode === "manual"
                    ? `단계 ${Math.min(manualStep, totalSteps)} / ${totalSteps} — 성공 ${activeSucc} / 방어차단 ${activeFail}`
                    : done ? `완료 — 성공 ${autoSucc} / 실패 ${autoFail} / 전체 ${totalSteps}`
                    : `단계 ${currentStep} / ${totalSteps}`}
              </span>
              <span style={{ color: activeFail > 0 ? "#f97316" : (done || manualDone || viewingHistory) ? "#4ade80" : "#38bdf8" }}>
                {viewingHistory ? "100" : pct}%
              </span>
            </div>
            <div style={{ height: 6, background: "#1e293b", borderRadius: 3, overflow: "hidden" }}>
              <div style={{ height: "100%", borderRadius: 3,
                background: activeFail > 0 ? "#f97316" : (done || manualDone || viewingHistory) ? "#22c55e" : "#38bdf8",
                width: viewingHistory ? "100%" : simMode === "manual"
                  ? `${totalSteps > 0 ? Math.round((Math.min(manualStep-1,totalSteps)/totalSteps)*100) : 0}%`
                  : `${pct}%`,
                transition: "width 0.4s ease" }}/>
            </div>
            <div style={{ display: "flex", gap: 4, marginTop: "0.5rem", flexWrap: "wrap" }}>
              {(scenario.steps ?? []).map(s => {
                const r = activeResults[s.step_number];
                const colors = {
                  success: { bg: "#14532d", border: "#22c55e60", color: "#4ade80", icon: "✓" },
                  failed:  { bg: "#450a0a", border: "#ef4444",   color: "#f87171", icon: "✗" },
                  current: { bg: "#1e3a5f", border: "#38bdf8",   color: "#7dd3fc", icon: "●" },
                  skipped: { bg: "#1e293b", border: "#475569",   color: "#475569", icon: "—" },
                };
                const c = r ? colors[r] : { bg: "#1e293b", border: "#334155", color: "#475569", icon: "○" };
                return (
                  <div key={s.step_number} title={`${s.step_number}. ${s.title}`}
                    style={{ display: "flex", alignItems: "center", gap: 4, padding: "3px 9px",
                      borderRadius: 10, fontSize: "0.7rem",
                      background: c.bg, border: `1px solid ${c.border}`, color: c.color }}>
                    <span style={{ fontSize: "0.6rem" }}>{c.icon}</span>{s.step_number}
                  </div>
                );
              })}
            </div>
          </div>

          {vizTab === "flow" && (
            <div style={{ background: "#070b10", border: "1px solid #1e293b",
              borderRadius: 8, padding: "1rem" }}>
              <AttackFlowDiagram steps={scenario.steps} stepResults={activeResults} currentStep={manualStep || currentStep}/>
            </div>
          )}
        </div>
      )}

      {/* 수동 모드: 현재 단계 카드 */}
      {simMode === "manual" && !viewingHistory && currentManualStepObj && !manualDone && (
        <div style={{ marginBottom: "1.25rem" }}>
          <ManualStepCard
            key={manualStep}
            step={currentManualStepObj}
            totalSteps={scenario?.steps.length ?? 0}
            labId={labId}
            scenarioId={scenario?.scenario_id ?? ""}
            onComplete={handleManualStepComplete}
            onSkip={handleManualSkip}
          />
        </div>
      )}

      {/* 자동 모드: 이벤트 로그 */}
      {simMode === "auto" && (displayEvents.length > 0 || viewingHistory) && vizTab === "log" && (
        <div ref={logRef} style={{ background: "#020617", border: "1px solid #1e293b",
          borderRadius: 8, padding: "0.75rem", minHeight: 180, maxHeight: 440, overflowY: "auto" }}>
          {displayEvents.map((ev, i) => {
            const st = evStyle(ev.event_type);
            if (ev.event_type === "log" && !ev.message) return null;
            return (
              <div key={i} style={{ marginBottom: "0.35rem", padding: "0.35rem 0.6rem",
                borderLeft: `3px solid ${st.border}`, background: st.bg, borderRadius: "0 4px 4px 0" }}>
                <div style={{ display: "flex", gap: "0.5rem", alignItems: "baseline" }}>
                  {ev.step > 0 && (
                    <span style={{ color: "#334155", fontSize: "0.68rem", minWidth: "4.5ch", flexShrink: 0 }}>
                      [{ev.step}/{totalSteps || viewingHistory?.totalSteps || "?"}]
                    </span>
                  )}
                  {st.label && (
                    <span style={{ color: st.color, fontSize: "0.7rem", minWidth: "8ch", flexShrink: 0 }}>{st.label}</span>
                  )}
                  <span style={{ color: ev.event_type === "step_failed" ? "#fca5a5"
                    : ev.event_type === "step_done" ? "#bbf7d0"
                    : ev.event_type === "defense_triggered" ? "#fed7aa" : "#cbd5e1", fontSize: "0.82rem" }}>
                    {ev.message}
                  </span>
                </div>
                {ev.detail && ev.event_type !== "log" && (
                  <div style={{ marginTop: "0.2rem", paddingLeft: ev.step > 0 ? "5ch" : "0",
                    color: "#475569", fontSize: "0.7rem", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                    {ev.detail.slice(0, 240)}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </main>
  );
}

export default function SimulationPage() {
  return (
    <Suspense fallback={
      <main style={{ padding: "2rem", maxWidth: 960, margin: "0 auto",
        fontFamily: "var(--font-sans)", color: "var(--ink)" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem",
          padding: "0.75rem 1rem", background: "var(--primary-glow)",
          border: "1px solid rgba(94,106,210,0.25)",
          borderRadius: "var(--radius-md)", marginTop: "2rem" }}>
          <span style={{ display: "inline-block", width: 14, height: 14,
            borderRadius: "50%", border: "2px solid var(--primary)",
            borderTopColor: "transparent", flexShrink: 0,
            animation: "spin 0.7s linear infinite" }}/>
          <span style={{ color: "var(--primary-hover)", fontSize: "13px" }}>로딩 중...</span>
        </div>
      </main>
    }>
      <SimulationContent />
    </Suspense>
  );
}
