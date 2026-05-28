"use client";
// frontend/src/components/FileUpload.tsx
import { useCallback, useState, useRef } from "react";
import { Upload, FileCode, AlertCircle } from "lucide-react";

const ALLOWED = [".ps1", ".js", ".py", ".vbs", ".bat", ".sh", ".ts"];
const MAX_MB = 2;

interface Props {
  onFile: (file: File) => void;
  disabled?: boolean;
}

export default function FileUpload({ onFile, disabled }: Props) {
  const [dragging, setDragging] = useState(false);
  const [error, setError]       = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const validate = (file: File): string | null => {
    const ext = "." + file.name.split(".").pop()?.toLowerCase();
    if (!ALLOWED.includes(ext))
      return `지원하지 않는 파일: ${ext} | 허용: ${ALLOWED.join(", ")}`;
    if (file.size > MAX_MB * 1024 * 1024)
      return `파일 크기 초과 (최대 ${MAX_MB}MB)`;
    if (file.size === 0) return "빈 파일입니다.";
    return null;
  };

  const handle = useCallback((file: File) => {
    const err = validate(file);
    if (err) { setError(err); return; }
    setError(null);
    onFile(file);
  }, [onFile]);

  const onDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files[0];
    if (file) handle(file);
  }, [handle]);

  return (
    <div className="w-full">
      <div
        onClick={() => !disabled && inputRef.current?.click()}
        onDragOver={(e) => { e.preventDefault(); if (!disabled) setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={!disabled ? onDrop : undefined}
        style={{
          border: `1.5px dashed ${dragging ? "#f59e0b" : error ? "#ef4444" : "#1f2937"}`,
          borderRadius: "12px",
          padding: "52px 24px",
          textAlign: "center",
          cursor: disabled ? "not-allowed" : "pointer",
          background: dragging ? "rgba(245,158,11,0.04)" : "rgba(255,255,255,0.015)",
          transition: "all 0.2s ease",
          opacity: disabled ? 0.5 : 1,
        }}
      >
        <input
          ref={inputRef}
          type="file"
          accept={ALLOWED.join(",")}
          style={{ display: "none" }}
          onChange={(e) => { const f = e.target.files?.[0]; if (f) handle(f); }}
          disabled={disabled}
        />

        <div style={{ marginBottom: "16px" }}>
          {dragging
            ? <Upload size={36} color="#f59e0b" style={{ margin: "0 auto" }} />
            : <FileCode size={36} color="#374151" style={{ margin: "0 auto" }} />
          }
        </div>

        <p style={{
          color: dragging ? "#f59e0b" : "#9ca3af",
          fontSize: "15px", fontWeight: 500, marginBottom: "8px",
          transition: "color 0.2s",
        }}>
          {dragging ? "드롭해서 분석 시작" : "스크립트 파일을 드래그하거나 클릭"}
        </p>
        <p style={{ color: "#374151", fontSize: "12px", fontFamily: "'JetBrains Mono', monospace" }}>
          {ALLOWED.join("  ·  ")} &nbsp;|&nbsp; 최대 {MAX_MB}MB
        </p>
      </div>

      {error && (
        <div style={{
          display: "flex", alignItems: "center", gap: "8px",
          marginTop: "12px", padding: "10px 14px",
          background: "rgba(239,68,68,0.08)",
          border: "1px solid rgba(239,68,68,0.25)",
          borderRadius: "8px",
        }}>
          <AlertCircle size={14} color="#ef4444" />
          <span style={{ color: "#fca5a5", fontSize: "13px" }}>{error}</span>
        </div>
      )}
    </div>
  );
}
