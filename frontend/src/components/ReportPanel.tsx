"use client";
// frontend/src/components/ReportPanel.tsx
import { AnalysisResult, RISK_META, formatBytes } from "@/lib/api";
import RiskGauge from "./RiskGauge";
import AttackChain from "./AttackChain";
import { Shield, FileCode, Cpu, Zap, AlertTriangle, CheckCircle, Clock, Coins } from "lucide-react";

interface Props { result: AnalysisResult; }

function Card({ children }: { children: React.ReactNode }) {
  return (
    <div style={{
      background: "#0a0c0f", border: "1px solid #1f2937",
      borderRadius: "12px", padding: "20px",
    }}>
      {children}
    </div>
  );
}

function SectionHeader({
  icon, title, badge, badgeColor,
}: { icon?: React.ReactNode; title: string; badge?: string; badgeColor?: string }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: "8px", marginBottom: "16px" }}>
      {icon && <span style={{ color: "#4b5563" }}>{icon}</span>}
      <span style={{ color: "#6b7280", fontSize: "12px", fontWeight: 500 }}>{title}</span>
      {badge && (
        <span style={{
          fontFamily: "'JetBrains Mono', monospace", fontSize: "10px",
          fontWeight: 700, letterSpacing: "0.08em",
          padding: "2px 7px", borderRadius: "4px",
          background: `${badgeColor}15`, color: badgeColor,
          border: `1px solid ${badgeColor}35`,
        }}>{badge}</span>
      )}
    </div>
  );
}

function MonoLabel({ children, style }: { children: React.ReactNode; style?: React.CSSProperties }) {
  return (
    <p style={{
      fontFamily: "'JetBrains Mono', monospace", fontSize: "10px",
      letterSpacing: "0.1em", color: "#374151",
      textTransform: "uppercase", ...style,
    }}>{children}</p>
  );
}

function MetaItem({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <MonoLabel style={{ marginBottom: "3px" }}>{label}</MonoLabel>
      <p style={{ color: "#4b5563", fontSize: "13px", fontFamily: "'JetBrains Mono', monospace" }}>{value}</p>
    </div>
  );
}

function ScoreBar({ value, color }: { value: number; color: string }) {
  return (
    <div style={{ height: "3px", borderRadius: "2px", background: "#111827", overflow: "hidden" }}>
      <div style={{
        height: "100%", width: `${Math.round(value * 100)}%`,
        background: color, borderRadius: "2px",
        boxShadow: `0 0 6px ${color}50`,
        transition: "width 0.8s ease",
      }} />
    </div>
  );
}

function Chip({ icon, label, color }: { icon: React.ReactNode; label: string; color: string }) {
  return (
    <div style={{
      display: "inline-flex", alignItems: "center", gap: "5px",
      padding: "3px 9px", borderRadius: "4px",
      background: `${color}10`, border: `1px solid ${color}28`,
      color, fontFamily: "'JetBrains Mono', monospace",
      fontSize: "10px", fontWeight: 600, letterSpacing: "0.05em",
      whiteSpace: "nowrap",
    }}>
      {icon} {label}
    </div>
  );
}

export default function ReportPanel({ result }: Props) {
  const { local, llm, llm_skipped } = result;
  const meta = RISK_META[local.risk_level];

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: "12px" }}>

      {/* 파일 메타 + 게이지 */}
      <Card>
        <div style={{ display: "flex", alignItems: "flex-start", gap: "24px", flexWrap: "wrap" }}>
          <RiskGauge score={local.risk_score} level={local.risk_level} />

          <div style={{ flex: 1, minWidth: "180px" }}>
            <div style={{ marginBottom: "16px" }}>
              <MonoLabel style={{ marginBottom: "4px" }}>파일</MonoLabel>
              <p style={{ color: "#d1d5db", fontSize: "14px", fontWeight: 500, fontFamily: "'JetBrains Mono', monospace" }}>
                {result.filename}
              </p>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: "12px" }}>
              <MetaItem label="언어"    value={result.lang_hint} />
              <MetaItem label="크기"    value={formatBytes(result.file_size_bytes)} />
              <MetaItem label="라인 수" value={`${result.line_count} lines`} />
              <MetaItem label="엔트로피" value={local.entropy.toFixed(2)} />
            </div>
          </div>

          <div style={{ display: "flex", flexDirection: "column", gap: "6px", alignSelf: "flex-start" }}>
            <Chip icon={<Clock size={11} />} label={`${result.processing_time_ms}ms`} color="#6b7280" />
            {llm_skipped
              ? <Chip icon={<Coins size={11} />}        label="TOKEN SAVED"              color="#22c55e" />
              : <Chip icon={<Zap size={11} />}          label={`${llm?.token_usage ?? 0} tokens`} color="#f59e0b" />
            }
            {result.truncated && <Chip icon={<AlertTriangle size={11} />} label="TRUNCATED" color="#f97316" />}
          </div>
        </div>
      </Card>

      {/* 로컬 모델 분석 결과 */}
      <Card>
        <SectionHeader icon={<Cpu size={13} />} title="로컬 모델 분석" badge="LOCAL AI" badgeColor="#a78bfa" />

        <div style={{ display: "flex", flexDirection: "column", gap: "14px" }}>
          {/* 점수 바 */}
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
              <MonoLabel>종합 위험도</MonoLabel>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", color: meta.color }}>
                {(local.risk_score * 100).toFixed(1)}%
              </span>
            </div>
            <ScoreBar value={local.risk_score} color={meta.color} />
          </div>

          <div>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "6px" }}>
              <MonoLabel>난독화 점수</MonoLabel>
              <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: "11px", color: "#60a5fa" }}>
                {(local.obfuscation_score * 100).toFixed(1)}%
              </span>
            </div>
            <ScoreBar value={local.obfuscation_score} color="#60a5fa" />
          </div>

          {/* 탐지 패턴 */}
          {local.pattern_labels.length > 0 && (
            <div>
              <MonoLabel style={{ marginBottom: "8px" }}>탐지 패턴</MonoLabel>
              <div style={{ display: "flex", flexWrap: "wrap", gap: "6px" }}>
                {local.pattern_labels.map((p) => (
                  <span key={p} style={{
                    fontFamily: "'JetBrains Mono', monospace", fontSize: "11px",
                    padding: "3px 10px", borderRadius: "4px",
                    background: "rgba(239,68,68,0.08)", color: "#fca5a5",
                    border: "1px solid rgba(239,68,68,0.2)",
                  }}>{p}</span>
                ))}
              </div>
            </div>
          )}

          {/* 난독화 기법 */}
          {local.obfuscation_techniques.length > 0 && (
            <div>
              <MonoLabel style={{ marginBottom: "8px" }}>난독화 기법</MonoLabel>
              <div style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                {local.obfuscation_techniques.map((t) => (
                  <div key={t} style={{ display: "flex", alignItems: "flex-start", gap: "8px" }}>
                    <span style={{ color: "#f59e0b", fontSize: "11px", marginTop: "1px" }}>⚑</span>
                    <span style={{ color: "#6b7280", fontSize: "13px", lineHeight: 1.5 }}>{t}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* 탐지 없음 */}
          {local.pattern_labels.length === 0 && local.obfuscation_techniques.length === 0 && (
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <CheckCircle size={14} color="#22c55e" />
              <span style={{ color: "#22c55e", fontSize: "13px" }}>악성 패턴 미탐지</span>
            </div>
          )}
        </div>
      </Card>

      {/* Claude API 심층 분석 */}
      {llm && !llm_skipped && (
        <Card>
          <SectionHeader icon={<Zap size={13} />} title="Claude API 심층 분석" badge="LLM" badgeColor="#f59e0b" />

          {llm.summary && (
            <div style={{
              padding: "12px 16px", marginBottom: "20px",
              background: "rgba(245,158,11,0.04)",
              border: "1px solid rgba(245,158,11,0.12)",
              borderRadius: "8px",
            }}>
              <p style={{ color: "#fcd34d", fontSize: "13px", lineHeight: 1.7 }}>{llm.summary}</p>
            </div>
          )}

          <AttackChain chain={llm.attack_chain} techniques={llm.mitre_techniques} />

          {llm.recommendation && (
            <div style={{ marginTop: "20px" }}>
              <SectionHeader icon={<Shield size={13} />} title="대응 방안" />
              <div style={{
                padding: "14px 16px",
                background: "rgba(34,197,94,0.04)",
                border: "1px solid rgba(34,197,94,0.12)",
                borderRadius: "8px",
              }}>
                <p style={{ color: "#86efac", fontSize: "13px", lineHeight: 1.7 }}>
                  {llm.recommendation}
                </p>
              </div>
            </div>
          )}
        </Card>
      )}

      {/* TOKEN SAVE 안내 */}
      {llm_skipped && (
        <Card>
          <div style={{ display: "flex", alignItems: "flex-start", gap: "12px" }}>
            <Coins size={16} color="#22c55e" style={{ marginTop: "1px", flexShrink: 0 }} />
            <div>
              <p style={{
                fontFamily: "'JetBrains Mono', monospace", fontSize: "12px",
                color: "#22c55e", fontWeight: 600, marginBottom: "4px",
              }}>
                TOKEN SAVED — LLM 호출 생략
              </p>
              <p style={{ color: "#374151", fontSize: "13px", lineHeight: 1.6 }}>
                위험도 점수 {(local.risk_score * 100).toFixed(1)}%가 임계값(50%) 미만으로
                Claude API 호출을 건너뛰었습니다. 로컬 모델 분석만으로 충분한 결과입니다.
              </p>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
}
