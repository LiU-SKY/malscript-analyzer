"use client";
// frontend/src/components/RiskGauge.tsx
import { RiskLevel, RISK_META } from "@/lib/api";

interface Props { score: number; level: RiskLevel; }

export default function RiskGauge({ score, level }: Props) {
  const meta  = RISK_META[level];
  const R     = 54;
  const cx    = 72;
  const cy    = 72;
  const sw    = 8;
  const circ  = 2 * Math.PI * R;
  const dash  = circ * Math.min(score, 1);
  const gap   = circ - dash;

  return (
    <div style={{ textAlign: "center" }}>
      <svg width={144} height={144} style={{ overflow: "visible", display: "block", margin: "0 auto" }}>
        {/* 트랙 */}
        <circle cx={cx} cy={cy} r={R} fill="none" stroke="#111827" strokeWidth={sw} />
        {/* 게이지 */}
        <circle
          cx={cx} cy={cy} r={R}
          fill="none" stroke={meta.color} strokeWidth={sw}
          strokeLinecap="round"
          strokeDasharray={`${dash} ${gap}`}
          strokeDashoffset={circ * 0.25}
          style={{ filter: `drop-shadow(0 0 6px ${meta.glow})`, transition: "stroke-dasharray 0.8s ease" }}
        />
        {/* 점수 */}
        <text x={cx} y={cy - 8} textAnchor="middle"
          fill={meta.color} fontSize="22" fontWeight="700"
          fontFamily="'JetBrains Mono', monospace">
          {(score * 100).toFixed(0)}
        </text>
        <text x={cx} y={cy + 10} textAnchor="middle"
          fill="#374151" fontSize="11" fontFamily="'JetBrains Mono', monospace">
          / 100
        </text>
        {/* 레이블 */}
        <text x={cx} y={cy + 28} textAnchor="middle"
          fill={meta.color} fontSize="11" fontWeight="600"
          fontFamily="'JetBrains Mono', monospace" letterSpacing="2">
          {meta.label}
        </text>
      </svg>
    </div>
  );
}
