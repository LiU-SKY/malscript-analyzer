// frontend/src/app/layout.tsx
import type { Metadata } from "next";
import "./globals.css";
import NavBar from "@/components/NavBar";

export const metadata: Metadata = {
  title: "MalScript Analyzer",
  description: "Multi-stage malicious script analysis — Local AI + Claude API",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="ko">
      <body style={{ margin: 0, background: "var(--canvas)", minHeight: "100vh" }}>
        <NavBar />
        {children}
      </body>
    </html>
  );
}
