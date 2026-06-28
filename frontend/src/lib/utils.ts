/**
 * SentinelAI — Utility Functions
 *
 * Shared helpers used across the application.
 * No business logic here — pure transformations and formatting.
 */

import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import type {
  AlertStatus,
  IncidentStatus,
  Severity,
  IncidentSeverity,
} from "@/types";

// ============================================================
// Tailwind class name merging
// ============================================================

/** Merge Tailwind classes safely, resolving conflicts. */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

// ============================================================
// Severity color maps
// Design source: DESIGN.md — SentinelAI severity system
// ============================================================

/** Returns the design-token Tailwind text color class for a severity level. */
export function severityTextColor(severity: Severity | null | undefined): string {
  switch (severity) {
    case "critical":
      return "text-[#f43f5e]";
    case "high":
      return "text-[#fa3abf]";
    case "medium":
      return "text-[#9c9af2]";
    case "low":
      return "text-[#afec73]";
    case "informational":
    default:
      return "text-[#878c99]";
  }
}

/** Returns the design-token Tailwind border/bg color class for severity badge. */
export function severityBadgeClasses(severity: Severity | null | undefined): string {
  switch (severity) {
    case "critical":
      return "border-[#f43f5e] text-[#f43f5e] bg-[rgba(244,63,94,0.08)]";
    case "high":
      return "border-[#fa3abf] text-[#fa3abf] bg-[rgba(250,58,191,0.08)]";
    case "medium":
      return "border-[#9c9af2] text-[#9c9af2] bg-[rgba(156,154,242,0.08)]";
    case "low":
      return "border-[#afec73] text-[#afec73] bg-[rgba(175,236,115,0.08)]";
    case "informational":
    default:
      return "border-[#878c99] text-[#878c99] bg-[rgba(135,140,153,0.08)]";
  }
}

/** Human-readable severity label with capitalization. */
export function severityLabel(severity: Severity | null | undefined): string {
  if (!severity) return "—";
  return severity.charAt(0).toUpperCase() + severity.slice(1);
}

// ============================================================
// Alert status color maps
// Design source: DESIGN.md — Alert status system
// ============================================================

export function alertStatusBadgeClasses(status: AlertStatus): string {
  switch (status) {
    case "new":
    case "open":
      return "border-[#f43f5e] text-[#f43f5e] bg-[rgba(244,63,94,0.08)]";
    case "triaging":
      return "border-[#d9f07c] text-[#d9f07c] bg-[rgba(217,240,124,0.08)]";
    case "in_progress":
      return "border-[#9c9af2] text-[#9c9af2] bg-[rgba(156,154,242,0.08)]";
    case "escalated":
      return "border-[#fa3abf] text-[#fa3abf] bg-[rgba(250,58,191,0.08)]";
    case "resolved":
      return "border-[#878c99] text-[#878c99] bg-[rgba(135,140,153,0.08)]";
    case "false_positive":
    case "suppressed":
      return "border-[#3b3e45] text-[#878c99] bg-[rgba(59,62,69,0.08)]";
    default:
      return "border-[#3b3e45] text-[#878c99] bg-transparent";
  }
}

export function alertStatusLabel(status: AlertStatus): string {
  const labels: Record<AlertStatus, string> = {
    new: "New",
    triaging: "Triaging",
    open: "Open",
    in_progress: "In Progress",
    escalated: "Escalated",
    resolved: "Resolved",
    false_positive: "False Positive",
    suppressed: "Suppressed",
  };
  return labels[status] ?? status;
}

// ============================================================
// Incident status color maps
// ============================================================

export function incidentStatusBadgeClasses(status: IncidentStatus): string {
  switch (status) {
    case "open":
      return "border-[#f43f5e] text-[#f43f5e] bg-[rgba(244,63,94,0.08)]";
    case "investigating":
      return "border-[#9c9af2] text-[#9c9af2] bg-[rgba(156,154,242,0.08)]";
    case "contained":
      return "border-[#a8ff53] text-[#a8ff53] bg-[rgba(168,255,83,0.08)]";
    case "eradicated":
      return "border-[#d9f07c] text-[#d9f07c] bg-[rgba(217,240,124,0.08)]";
    case "recovered":
      return "border-[#afec73] text-[#afec73] bg-[rgba(175,236,115,0.08)]";
    case "closed":
    case "false_positive":
      return "border-[#3b3e45] text-[#878c99] bg-[rgba(59,62,69,0.08)]";
    default:
      return "border-[#3b3e45] text-[#878c99] bg-transparent";
  }
}

export function incidentStatusLabel(status: IncidentStatus): string {
  const labels: Record<IncidentStatus, string> = {
    open: "Open",
    investigating: "Investigating",
    contained: "Contained",
    eradicated: "Eradicated",
    recovered: "Recovered",
    closed: "Closed",
    false_positive: "False Positive",
  };
  return labels[status] ?? status;
}

// ============================================================
// Source label
// ============================================================

export function sourceLabel(source: string): string {
  return source.toUpperCase();
}

// ============================================================
// Date / time formatting
// ============================================================

const relativeFormatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });

/** Format an ISO 8601 string as a compact absolute timestamp. */
export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Intl.DateTimeFormat("en-US", {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    }).format(new Date(iso));
  } catch {
    return iso;
  }
}

/** Format an ISO 8601 string as a relative time (e.g. "3 minutes ago"). */
export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    const now = Date.now();
    const then = new Date(iso).getTime();
    const diffSec = Math.round((then - now) / 1000);
    const absDiff = Math.abs(diffSec);

    if (absDiff < 60) return relativeFormatter.format(diffSec, "second");
    if (absDiff < 3600) return relativeFormatter.format(Math.round(diffSec / 60), "minute");
    if (absDiff < 86400) return relativeFormatter.format(Math.round(diffSec / 3600), "hour");
    return relativeFormatter.format(Math.round(diffSec / 86400), "day");
  } catch {
    return iso;
  }
}

/** Format an ISO 8601 string as a full date for log/report headers. */
export function formatFullDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  try {
    return new Intl.DateTimeFormat("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
      timeZoneName: "short",
    }).format(new Date(iso));
  } catch {
    return iso;
  }
}

// ============================================================
// String helpers
// ============================================================

/** Truncate a string to a max length, appending "…". */
export function truncate(str: string, maxLen: number): string {
  if (str.length <= maxLen) return str;
  return str.slice(0, maxLen - 1) + "…";
}

/** Extract initials from a name string. */
export function initials(name: string): string {
  return name
    .split(/\s+/)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? "")
    .join("");
}

// ============================================================
// Number helpers
// ============================================================

/** Format a number with compact suffix (1.2k, 3.5M). */
export function formatCompact(n: number): string {
  return new Intl.NumberFormat("en-US", {
    notation: "compact",
    maximumFractionDigits: 1,
  }).format(n);
}

/** Format a float as a percentage string. */
export function formatPercent(n: number, decimals = 1): string {
  return `${(n * 100).toFixed(decimals)}%`;
}

/** Format a confidence score (0.0–1.0) as a percentage. */
export function formatConfidence(n: number): string {
  return `${Math.round(n * 100)}%`;
}

// ============================================================
// Severity ordering (for sorting)
// ============================================================

const SEVERITY_ORDER: Record<Severity | IncidentSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

export function compareSeverity(
  a: Severity | IncidentSeverity | null | undefined,
  b: Severity | IncidentSeverity | null | undefined
): number {
  const aOrder = a ? (SEVERITY_ORDER[a as Severity] ?? 99) : 99;
  const bOrder = b ? (SEVERITY_ORDER[b as Severity] ?? 99) : 99;
  return aOrder - bOrder;
}

// ============================================================
// ID display helpers
// ============================================================

/** Shorten a UUID or long ID for display (first 8 chars). */
export function shortId(id: string): string {
  return id.slice(0, 8).toUpperCase();
}
