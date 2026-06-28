/**
 * SentinelAI — Badge Component
 *
 * Renders severity badges, status chips, source tags, and MITRE tags.
 *
 * Design rules (DESIGN.md):
 *  - Severity and status colors from design token system only
 *  - Pill shape (9999px radius) for labels/tags per spec
 *  - 4px radius for rectangular variants
 *  - No fill backgrounds larger than a badge surface
 *  - Geist font, 12-13px, weight 500
 */

import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import type { AlertStatus, IncidentStatus, Severity } from "@/types";
import {
  severityBadgeClasses,
  severityLabel,
  alertStatusBadgeClasses,
  alertStatusLabel,
  incidentStatusBadgeClasses,
  incidentStatusLabel,
} from "@/lib/utils";

// ── Generic Badge ──────────────────────────────────────────────────────────

export type BadgeVariant = "pill" | "rect";

export interface BadgeProps {
  children: ReactNode;
  variant?: BadgeVariant;
  className?: string;
  dot?: boolean;
}

export function Badge({ children, variant = "pill", className, dot }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 font-medium border text-[12px] leading-none",
        "font-[family-name:var(--font-geist)]",
        variant === "pill" ? "rounded-full px-2 py-0.5" : "rounded-[4px] px-1.5 py-0.5",
        className
      )}
    >
      {dot && (
        <span className="inline-block h-1.5 w-1.5 rounded-full bg-current flex-shrink-0" />
      )}
      {children}
    </span>
  );
}

// ── Severity Badge ─────────────────────────────────────────────────────────

export function SeverityBadge({
  severity,
  variant = "rect",
}: {
  severity: Severity | null | undefined;
  variant?: BadgeVariant;
}) {
  return (
    <Badge
      variant={variant}
      className={cn("uppercase tracking-wide text-[11px]", severityBadgeClasses(severity))}
      dot
    >
      {severityLabel(severity)}
    </Badge>
  );
}

// ── Alert Status Badge ─────────────────────────────────────────────────────

export function AlertStatusBadge({
  status,
  variant = "rect",
}: {
  status: AlertStatus;
  variant?: BadgeVariant;
}) {
  return (
    <Badge variant={variant} className={alertStatusBadgeClasses(status)}>
      {alertStatusLabel(status)}
    </Badge>
  );
}

// ── Incident Status Badge ──────────────────────────────────────────────────

export function IncidentStatusBadge({
  status,
  variant = "rect",
}: {
  status: IncidentStatus;
  variant?: BadgeVariant;
}) {
  return (
    <Badge variant={variant} className={incidentStatusBadgeClasses(status)}>
      {incidentStatusLabel(status)}
    </Badge>
  );
}

// ── Source Badge ───────────────────────────────────────────────────────────

export function SourceBadge({ source }: { source: string }) {
  return (
    <Badge
      variant="rect"
      className="border-[#3b3e45] text-[#878c99] bg-transparent uppercase tracking-widest text-[10px]"
    >
      {source}
    </Badge>
  );
}

// ── MITRE Technique Badge ──────────────────────────────────────────────────

export function MitreBadge({ id, name }: { id: string; name?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-[4px] border border-[#272a2e]",
        "bg-[#121317] px-2 py-0.5 text-[12px]"
      )}
      title={name}
    >
      <span className="font-mono text-[#a8ff53] text-[11px]">{id}</span>
      {name && <span className="text-[#878c99] truncate max-w-[140px]">{name}</span>}
    </span>
  );
}

// ── Tag Badge ──────────────────────────────────────────────────────────────

export function TagBadge({ label }: { label: string }) {
  return (
    <Badge
      variant="pill"
      className="border-[#272a2e] text-[#878c99] bg-transparent text-[11px]"
    >
      {label}
    </Badge>
  );
}
