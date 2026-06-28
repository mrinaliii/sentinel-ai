/**
 * SentinelAI — StatCard Component
 *
 * Dashboard stat card per DESIGN.md spec:
 *  - Container: bg #1c1e21, border 1px #272a2e, 4px radius, 24px padding
 *  - Metric: Satoshi 30px weight 500, #e5e7eb
 *  - Label: Geist 14px, #878c99
 *  - Trend positive: #a8ff53 (Signal Lime)
 *  - Trend negative: #f43f5e (Mute Red)
 *
 * No drop shadows. No gradients.
 */

import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────────────────

export type TrendDirection = "up" | "down" | "neutral";

export interface StatCardProps {
  label: string;
  value: string | number;
  /** Optional sub-value shown below the metric in smaller text. */
  subValue?: string;
  /** Trend indicator: direction + magnitude string (e.g. "+23%") */
  trend?: {
    direction: TrendDirection;
    label: string;
    /** Whether "up" is positive (default true). Some metrics are better when down (e.g. alert count). */
    invertColors?: boolean;
  };
  icon?: ReactNode;
  /** Accent color override for the metric value. Falls back to #e5e7eb. */
  accentColor?: string;
  className?: string;
  /** Click handler for navigating to detail view. */
  onClick?: () => void;
}

// ── Component ──────────────────────────────────────────────────────────────

export function StatCard({
  label,
  value,
  subValue,
  trend,
  icon,
  accentColor,
  className,
  onClick,
}: StatCardProps) {
  const trendColor = getTrendColor(trend);

  return (
    <div
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      onClick={onClick}
      onKeyDown={onClick ? (e) => e.key === "Enter" && onClick() : undefined}
      className={cn(
        "rounded-[4px] border border-[#272a2e] bg-[#1c1e21] p-6",
        "transition-colors duration-100",
        onClick && "cursor-pointer hover:border-[#3b3e45] focus-visible:outline focus-visible:outline-1 focus-visible:outline-[#a8ff53]",
        className
      )}
    >
      {/* Header: label + icon */}
      <div className="flex items-start justify-between gap-3 mb-3">
        <span className="text-[13px] text-[#878c99] font-[family-name:var(--font-geist)] uppercase tracking-wider">
          {label}
        </span>
        {icon && (
          <span className="text-[#878c99] flex-shrink-0">{icon}</span>
        )}
      </div>

      {/* Metric value */}
      <div className="flex items-end gap-3">
        <span
          className="font-[family-name:var(--font-satoshi)] text-[30px] font-[500] leading-none"
          style={{ color: accentColor ?? "#e5e7eb" }}
        >
          {value}
        </span>

        {/* Trend badge */}
        {trend && (
          <span
            className={cn(
              "text-[13px] font-[500] mb-0.5 flex items-center gap-0.5",
              trendColor
            )}
          >
            <TrendArrow direction={trend.direction} />
            {trend.label}
          </span>
        )}
      </div>

      {/* Sub-value */}
      {subValue && (
        <p className="mt-1 text-[13px] text-[#878c99] font-[family-name:var(--font-geist)]">
          {subValue}
        </p>
      )}
    </div>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────────

function getTrendColor(trend?: StatCardProps["trend"]): string {
  if (!trend) return "";
  const { direction, invertColors } = trend;
  const isPositive = invertColors
    ? direction === "down"
    : direction === "up";
  const isNegative = invertColors
    ? direction === "up"
    : direction === "down";

  if (isPositive) return "text-[#a8ff53]";
  if (isNegative) return "text-[#f43f5e]";
  return "text-[#878c99]";
}

function TrendArrow({ direction }: { direction: TrendDirection }) {
  if (direction === "up") {
    return (
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
        <path d="M18 15l-6-6-6 6" />
      </svg>
    );
  }
  if (direction === "down") {
    return (
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
        <path d="M6 9l6 6 6-6" />
      </svg>
    );
  }
  return null;
}
