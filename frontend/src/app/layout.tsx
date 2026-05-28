// frontend/src/app/layout.tsx
import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "MalScript Analyzer",
  description: "멀티스테이지 악성 스크립트 분석 플랫폼 — 로컬 AI + Claude API",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ko">
      <body>{children}</body>
    </html>
  );
}
