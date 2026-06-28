/**
 * SentinelAI — Topbar / Header
 *
 * Design spec:
 *  - Height: 48px
 *  - Background: #121317 (Ink Well)
 *  - Bottom border: 1px #272a2e
 *  - No drop shadow
 *  - Contains: breadcrumb/page title, global search trigger, notification bell, user actions
 */

import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

// ── Component ──────────────────────────────────────────────────────────────

export interface HeaderProps {
  /** Page title or breadcrumb shown on the left. */
  title: ReactNode;
  /** Secondary breadcrumb path components. */
  breadcrumb?: Array<{ label: string; href?: string }>;
  /** Right-side action buttons/controls. */
  actions?: ReactNode;
  /** Mobile sidebar toggle callback. */
  onMenuClick?: () => void;
}

export function Header({ title, breadcrumb, actions, onMenuClick }: HeaderProps) {
  return (
    <header
      className={cn(
        "h-12 flex-shrink-0 flex items-center justify-between px-4 gap-4",
        "border-b border-[#272a2e] bg-[#121317]",
        "sticky top-0 z-20"
      )}
      role="banner"
    >
      {/* Left: hamburger (mobile) + title */}
      <div className="flex items-center gap-3 min-w-0">
        {/* Mobile menu button */}
        {onMenuClick && (
          <button
            type="button"
            onClick={onMenuClick}
            aria-label="Open navigation menu"
            className={cn(
              "lg:hidden flex-shrink-0 rounded-[4px] p-1.5",
              "text-[#878c99] hover:text-[#e5e7eb] hover:bg-[rgba(255,255,255,0.06)]",
              "focus-visible:outline focus-visible:outline-1 focus-visible:outline-[#a8ff53]"
            )}
          >
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M3 12h18M3 6h18M3 18h18" strokeLinecap="round" />
            </svg>
          </button>
        )}

        {/* Breadcrumb + title */}
        <div className="min-w-0">
          {breadcrumb && breadcrumb.length > 0 && (
            <nav aria-label="Breadcrumb" className="flex items-center gap-1 mb-0.5">
              {breadcrumb.map((crumb, i) => (
                <span key={i} className="flex items-center gap-1">
                  {i > 0 && (
                    <svg
                      width="10"
                      height="10"
                      viewBox="0 0 24 24"
                      fill="none"
                      stroke="currentColor"
                      strokeWidth="2"
                      className="text-[#3b3e45]"
                    >
                      <path d="M9 18l6-6-6-6" />
                    </svg>
                  )}
                  <span className="text-[11px] text-[#878c99] uppercase tracking-wider">
                    {crumb.label}
                  </span>
                </span>
              ))}
            </nav>
          )}

          <h1
            className={cn(
              "font-[family-name:var(--font-satoshi)] font-[500] truncate",
              breadcrumb && breadcrumb.length > 0
                ? "text-[14px] text-[#e5e7eb]"
                : "text-[15px] text-[#e5e7eb]"
            )}
          >
            {title}
          </h1>
        </div>
      </div>

      {/* Right: action area */}
      {actions && (
        <div className="flex items-center gap-2 flex-shrink-0">
          {actions}
        </div>
      )}
    </header>
  );
}

// ── Header stat pill (small metric shown in header for context) ────────────

export function HeaderStat({
  label,
  value,
  color,
}: {
  label: string;
  value: string | number;
  color?: string;
}) {
  return (
    <span className="hidden md:flex items-center gap-1.5 text-[13px]">
      <span className="text-[#878c99]">{label}</span>
      <span
        className="font-mono font-[500]"
        style={{ color: color ?? "#e5e7eb" }}
      >
        {value}
      </span>
    </span>
  );
}
