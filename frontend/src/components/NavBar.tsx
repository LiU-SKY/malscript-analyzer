// frontend/src/components/NavBar.tsx — Linear.app design
"use client";
import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV_LINKS = [
  { href: "/",           label: "Analyze" },
  { href: "/scenario",   label: "Scenario" },
  { href: "/lab",        label: "Docker Lab" },
  { href: "/simulation", label: "Simulation" },
  { href: "/monitor",    label: "Monitor" },
];

export default function NavBar() {
  const pathname = usePathname();

  return (
    <nav style={{
      display: "flex",
      alignItems: "center",
      gap: "2px",
      padding: "0 1.5rem",
      height: "44px",
      background: "var(--canvas)",
      borderBottom: "1px solid var(--hairline)",
      position: "sticky",
      top: 0,
      zIndex: 50,
    }}>
      <Link href="/" style={{
        display: "flex",
        alignItems: "center",
        gap: "7px",
        marginRight: "12px",
        textDecoration: "none",
      }}>
        <span style={{
          display: "inline-flex",
          alignItems: "center",
          justifyContent: "center",
          width: "22px",
          height: "22px",
          borderRadius: "5px",
          background: "var(--primary)",
          fontSize: "11px",
          fontWeight: 700,
          color: "#fff",
          fontFamily: "var(--font-mono)",
          flexShrink: 0,
        }}>M</span>
        <span style={{
          color: "var(--ink)",
          fontWeight: 600,
          fontSize: "13px",
          letterSpacing: "-0.02em",
          whiteSpace: "nowrap",
        }}>MalScript</span>
      </Link>

      <div style={{
        width: "1px",
        height: "16px",
        background: "var(--hairline-strong)",
        marginRight: "12px",
        flexShrink: 0,
      }} />

      {NAV_LINKS.map(({ href, label }) => {
        const active = pathname === href;
        return (
          <NavLink key={href} href={href} label={label} active={active} />
        );
      })}
    </nav>
  );
}

function NavLink({ href, label, active }: { href: string; label: string; active: boolean }) {
  return (
    <Link
      href={href}
      style={{
        color: active ? "var(--ink)" : "var(--ink-subtle)",
        textDecoration: "none",
        padding: "0.25rem 0.6rem",
        borderRadius: "var(--radius-xs)",
        fontSize: "13px",
        fontWeight: active ? 500 : 400,
        letterSpacing: "-0.01em",
        background: active ? "var(--surface-2)" : "transparent",
        transition: "background 0.1s, color 0.1s",
        position: "relative",
      }}
      onMouseEnter={(e) => {
        if (!active) {
          e.currentTarget.style.background = "var(--surface-1)";
          e.currentTarget.style.color = "var(--ink-muted)";
        }
      }}
      onMouseLeave={(e) => {
        if (!active) {
          e.currentTarget.style.background = "transparent";
          e.currentTarget.style.color = "var(--ink-subtle)";
        }
      }}
    >
      {label}
      {active && (
        <span style={{
          position: "absolute",
          bottom: "-0.26rem",
          left: "0.6rem",
          right: "0.6rem",
          height: "1.5px",
          background: "var(--primary)",
          borderRadius: "var(--radius-full)",
        }} />
      )}
    </Link>
  );
}
