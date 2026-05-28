"use client";
// frontend/src/app/page.tsx
import { useState, useEffect } from "react";
import { analyzeFile, fetchHealth, AnalysisResult, HealthResponse } from "@/lib/api";
import FileUpload from "@/components/FileUpload";
import ReportPanel from "@/components/ReportPanel";
import { Shield, Activity, Circle, Loader2 } from "lucide-react";

type Phase = "idle" | "loading" | "done" | "error";

const STEPS = ["전처리", "로컬 AI 분석", "위험도 판단", "리포트 생성"] as const;

function StatusDot({ on, label, offColor = "#ef4444" }: { on: boolean; label: string; offColor?: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "5px",
      fontFamily: "'JetBrains Mono', monospace", fontSize: "11px",
      color: on ? "#22c55e" : offColor }}>
      <span style={{
        width: "6px", height: "6px", borderRadius: "50%",
        background: on ? "#22c55e" : offColor,
        boxShadow: on ? "0 0 5px #22c55e" : "none",
        display: "inline-block", flexShrink: 0,
      }} />
      {label}
    </div>
  );
}

export default function Page() {
  const [phase,  setPhase]  = useState<Phase>("idle");
  const [step,   setStep]   = useState(0);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [errMsg, setErrMsg] = useState("");
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    const check = () => fetchHealth().then(setHealth).catch(() => setHealth(null));
    check();
    const id = setInterval(check, 5000);
    return () => clearInterval(id);
  }, []);

  async function handleFile(file: File) {
    setPhase("loading");
    setResult(null);
    setErrMsg("");
    setStep(0);

    const t1 = setTimeout(() => setStep(1), 400);
    const t2 = setTimeout(() => setStep(2), 900);
    const t3 = setTimeout(() => setStep(3), 1400);

    try {
      const res = await analyzeFile(file);
      clearTimeout(t1); clearTimeout(t2); clearTimeout(t3);
      setStep(3);
      if (!res.success || !res.result) throw new Error(res.error ?? "분석 실패");
      setResult(res.result);
      setPhase("done");
    } catch (e: unknown) {
      clearTimeout(t1); clearTimeout(t2); clearTimeout(t3);
      setErrMsg(e instanceof Error ? e.message : "알 수 없는 오류");
      setPhase("error");
    }
  }

  return (
    <main style={{ minHeight: "100vh", background: "#060809" }}>

      {/* 헤더 */}
      <header style={{
        borderBottom: "1px solid #0f1520",
        padding: "0 24px",
        display: "flex", alignItems: "center", justifyContent: "space-between",
        height: "52px",
        background: "rgba(6,8,9,0.95)",
        backdropFilter: "blur(8px)",
        position: "sticky", top: 0, zIndex: 50,
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <Shield size={16} color="#7c3aed" />
          <span style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: "13px", fontWeight: 700,
            letterSpacing: "0.1em", color: "#d1d5db",
          }}>
            MALSCRIPT ANALYZER
          </span>
          <span style={{
            fontFamily: "'JetBrains Mono', monospace", fontSize: "10px",
            padding: "1px 6px", borderRadius: "3px",
            background: "#111827", color: "#374151", letterSpacing: "0.06em",
          }}>v1.0</span>
        </div>

        <div style={{ display: "flex", alignItems: "center", gap: "16px" }}>
          <StatusDot on={!!health} label={health ? "API 연결" : "API 끊김"} />
          <StatusDot
            on={health?.ollama_available ?? false}
            label={health?.ollama_available ? `Ollama: ${health.model_loaded}` : "Ollama 미연결"}
            offColor="#f59e0b"
          />
        </div>
      </header>

      <div style={{ maxWidth: "720px", margin: "0 auto", padding: "44px 24px 80px" }}>

        {/* 타이틀 */}
        <div style={{ marginBottom: "32px" }}>
          <h1 style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: "26px", fontWeight: 700,
            color: "#f9fafb", letterSpacing: "-0.02em", marginBottom: "10px",
          }}>
            Script Analysis
          </h1>
          <p style={{ color: "#374151", fontSize: "13px", lineHeight: 1.7 }}>
            PowerShell · JavaScript · Python · VBScript 스크립트를 업로드하면
            로컬 AI가 1차 분류 후 위험도 ≥ 50%인 경우에만 Claude API로
            MITRE ATT&CK 매핑 및 대응 방안을 생성합니다.
          </p>
        </div>

        {/* 업로드 */}
        <FileUpload onFile={handleFile} disabled={phase === "loading"} />

        {/* 파이프라인 진행 */}
        {phase === "loading" && (
          <div style={{
            marginTop: "24px", background: "#0a0c0f",
            border: "1px solid #1f2937", borderRadius: "12px", padding: "18px 20px",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "14px" }}>
              <Loader2 size={13} color="#7c3aed"
                style={{ animation: "spin 1s linear infinite" }} />
              <span style={{
                fontFamily: "'JetBrains Mono', monospace", fontSize: "11px",
                color: "#374151", letterSpacing: "0.08em",
              }}>ANALYZING</span>
            </div>

            <div style={{ display: "flex", gap: "6px" }}>
              {STEPS.map((s, i) => {
                const done    = i < step;
                const current = i === step;
                return (
                  <div key={s} style={{
                    flex: 1, padding: "8px 10px",
                    background: done ? "rgba(124,58,237,0.07)"
                                : current ? "rgba(124,58,237,0.03)" : "transparent",
                    border: `1px solid ${done ? "#7c3aed40" : current ? "#7c3aed18" : "#1f2937"}`,
                    borderRadius: "6px", transition: "all 0.3s ease",
                  }}>
                    <div style={{ display: "flex", alignItems: "center", gap: "5px" }}>
                      {done
                        ? <Circle size={7} color="#7c3aed" fill="#7c3aed" />
                        : current
                          ? <Activity size={7} color="#7c3aed" />
                          : <Circle size={7} color="#1f2937" />
                      }
                      <span style={{
                        fontFamily: "'JetBrains Mono', monospace", fontSize: "10px",
                        color: done ? "#7c3aed" : current ? "#4b5563" : "#1f2937",
                      }}>{s}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* 오류 */}
        {phase === "error" && (
          <div style={{
            marginTop: "20px", padding: "16px 20px",
            background: "rgba(239,68,68,0.06)",
            border: "1px solid rgba(239,68,68,0.2)",
            borderRadius: "10px",
          }}>
            <p style={{
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: "11px", color: "#ef4444", marginBottom: "6px",
            }}>ERROR</p>
            <p style={{ color: "#fca5a5", fontSize: "13px", lineHeight: 1.6 }}>{errMsg}</p>
            <button
              onClick={() => setPhase("idle")}
              style={{
                marginTop: "12px", fontFamily: "'JetBrains Mono', monospace",
                fontSize: "11px", color: "#4b5563",
                background: "none", border: "1px solid #1f2937",
                borderRadius: "4px", padding: "4px 12px", cursor: "pointer",
              }}
            >다시 시도</button>
          </div>
        )}

        {/* 분석 결과 */}
        {phase === "done" && result && (
          <div style={{ marginTop: "28px" }}>
            <div style={{
              display: "flex", alignItems: "center",
              justifyContent: "space-between", marginBottom: "14px",
            }}>
              <span style={{
                fontFamily: "'JetBrains Mono', monospace", fontSize: "10px",
                color: "#374151", letterSpacing: "0.1em",
              }}>ANALYSIS RESULT</span>
              <button
                onClick={() => { setPhase("idle"); setResult(null); }}
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: "11px", color: "#374151",
                  background: "none", border: "1px solid #1f2937",
                  borderRadius: "4px", padding: "3px 10px", cursor: "pointer",
                }}
              >새 파일 분석</button>
            </div>
            <ReportPanel result={result} />
          </div>
        )}
      </div>

      <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>
    </main>
  );
}
