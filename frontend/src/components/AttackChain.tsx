"use client";
// frontend/src/components/AttackChain.tsx
import { MitreTechnique } from "@/lib/api";
import { ExternalLink } from "lucide-react";

interface Props {
  chain: string[];
  techniques: MitreTechnique[];
}

const TACTIC_COLORS: Record<string, string> = {
  "Execution":              "#a78bfa",
  "Defense Evasion":        "#60a5fa",
  "Persistence":            "#f59e0b",
  "Privilege Escalation":   "#f97316",
  "Credential Access":      "#ef4444",
  "Discovery":              "#34d399",
  "Command and Control":    "#fb923c",
  "Exfiltration":           "#e879f9",
  "Impact":                 "#f87171",
};

function MonoLabel({ children }: { children: React.ReactNode }) {
  return (
    <p style={{
      fontFamily: "'JetBrains Mono', monospace", fontSize: "10px",
      letterSpacing: "0.1em", color: "#374151",
      textTransform: "uppercase", marginBottom: "12px",
    }}>
      {children}
    </p>
  );
}

export default function AttackChain({ chain, techniques }: Props) {
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "28px" }}>

      {/* 공격 체인 타임라인 */}
      {chain.length > 0 && (
        <div>
          <MonoLabel>공격 체인</MonoLabel>
          <div style={{ position: "relative", paddingLeft: "28px" }}>
            <div style={{
              position: "absolute", left: "8px", top: "6px", bottom: "6px",
              width: "1px",
              background: "linear-gradient(to bottom, #1f2937, transparent)",
            }} />
            {chain.map((step, i) => (
              <div key={i} style={{ position: "relative", marginBottom: i < chain.length - 1 ? "16px" : 0 }}>
                <div style={{
                  position: "absolute", left: "-24px", top: "6px",
                  width: "9px", height: "9px", borderRadius: "50%",
                  background: i === 0 ? "#ef4444" : i === chain.length - 1 ? "#22c55e" : "#1f2937",
                  border: `2px solid ${i === 0 ? "#ef4444" : i === chain.length - 1 ? "#22c55e" : "#374151"}`,
                  boxShadow: i === 0 ? "0 0 8px rgba(239,68,68,0.5)" : "none",
                }} />
                <div style={{
                  background: "#0a0c0f", border: "1px solid #1f2937",
                  borderRadius: "8px", padding: "10px 14px",
                }}>
                  <span style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: "10px", color: "#374151", marginRight: "10px",
                  }}>
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <span style={{ color: "#9ca3af", fontSize: "13px", lineHeight: 1.6 }}>{step}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* MITRE ATT&CK 기법 배지 */}
      {techniques.length > 0 && (
        <div>
          <MonoLabel>MITRE ATT&CK 매핑</MonoLabel>
          <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
            {techniques.map((t) => {
              const color = TACTIC_COLORS[t.tactic] ?? "#94a3b8";
              return (
                <a
                  key={t.technique_id}
                  href={t.url}
                  target="_blank"
                  rel="noreferrer"
                  title={`${t.technique_id} — ${t.tactic}`}
                  style={{
                    display: "inline-flex", alignItems: "center", gap: "6px",
                    padding: "6px 12px",
                    background: `${color}10`,
                    border: `1px solid ${color}35`,
                    borderRadius: "6px",
                    textDecoration: "none",
                    transition: "background 0.15s, border-color 0.15s",
                  }}
                  onMouseEnter={(e) => {
                    e.currentTarget.style.background = `${color}20`;
                    e.currentTarget.style.borderColor = `${color}60`;
                  }}
                  onMouseLeave={(e) => {
                    e.currentTarget.style.background = `${color}10`;
                    e.currentTarget.style.borderColor = `${color}35`;
                  }}
                >
                  <span style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize: "11px", fontWeight: 600, color,
                  }}>
                    {t.technique_id}
                  </span>
                  <span style={{ fontSize: "12px", color: "#6b7280" }}>{t.name}</span>
                  <span style={{
                    fontSize: "10px", padding: "1px 6px", borderRadius: "3px",
                    background: `${color}15`, color: `${color}cc`,
                  }}>
                    {t.tactic}
                  </span>
                  <ExternalLink size={10} color={`${color}70`} />
                </a>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
