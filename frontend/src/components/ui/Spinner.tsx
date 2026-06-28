/**
 * SentinelAI — Spinner Component
 *
 * Minimal loading indicator using the Signal Lime accent color.
 * No CSS animations that could be distracting.
 * Uses CSS border-based spinner — no SVG animation dependency.
 */

import { cn } from "@/lib/utils";

export type SpinnerSize = "xs" | "sm" | "md" | "lg";

export interface SpinnerProps {
  size?: SpinnerSize;
  className?: string;
  /** Accessible label for screen readers. */
  label?: string;
}

const sizes: Record<SpinnerSize, string> = {
  xs: "h-3 w-3 border",
  sm: "h-4 w-4 border",
  md: "h-5 w-5 border-2",
  lg: "h-8 w-8 border-2",
};

export function Spinner({ size = "md", className, label = "Loading…" }: SpinnerProps) {
  return (
    <span role="status" aria-label={label} className="inline-flex items-center">
      <span
        className={cn(
          "inline-block animate-spin rounded-full",
          "border-[#3b3e45] border-t-[#a8ff53]",
          sizes[size],
          className
        )}
      />
      <span className="sr-only">{label}</span>
    </span>
  );
}

// ── Full-page loading overlay ──────────────────────────────────────────────

export function PageSpinner({ label = "Loading page…" }: { label?: string }) {
  return (
    <div
      className="flex h-full min-h-[240px] w-full items-center justify-center"
      role="status"
      aria-label={label}
    >
      <div className="flex flex-col items-center gap-3">
        <Spinner size="lg" />
        <p className="text-[13px] text-[#878c99]">{label}</p>
      </div>
    </div>
  );
}

// ── Inline loading row (for tables) ───────────────────────────────────────

export function TableSpinner({ colSpan }: { colSpan: number }) {
  return (
    <tr>
      <td colSpan={colSpan} className="py-10 text-center">
        <Spinner size="md" label="Loading rows…" />
      </td>
    </tr>
  );
}
