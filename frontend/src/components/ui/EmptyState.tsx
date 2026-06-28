/**
 * SentinelAI — EmptyState & ErrorState Components
 *
 * Used everywhere a data list or page has no results, a fetch error,
 * or a first-time empty experience.
 *
 * Design rules:
 *  - No decorative illustrations — just icon + text
 *  - Icon in #3b3e45 (graphite hairline), text in #878c99 (fog)
 *  - Heading in #e5e7eb (bone) if present
 *  - Optional action button (uses Button component)
 *  - No cards, no drop shadows
 */

import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { Button } from "./Button";

// ── Empty State ────────────────────────────────────────────────────────────

export interface EmptyStateProps {
  /** Icon element (from lucide-react or inline SVG). Should be ~32px. */
  icon?: ReactNode;
  /** Primary heading line. */
  heading?: string;
  /** Supporting description. */
  description?: string;
  /** Optional CTA. */
  action?: {
    label: string;
    onClick: () => void;
    variant?: "primary" | "ghost" | "outline";
  };
  className?: string;
}

export function EmptyState({
  icon,
  heading = "Nothing here yet",
  description,
  action,
  className,
}: EmptyStateProps) {
  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center py-16 px-6 text-center",
        className
      )}
      role="status"
    >
      {icon && (
        <span className="mb-4 text-[#3b3e45]" aria-hidden>
          {icon}
        </span>
      )}

      <p className="text-[15px] font-[500] text-[#b5b8c0] font-[family-name:var(--font-geist)]">
        {heading}
      </p>

      {description && (
        <p className="mt-1 text-[13px] text-[#878c99] max-w-sm">
          {description}
        </p>
      )}

      {action && (
        <Button
          variant={action.variant ?? "ghost"}
          size="md"
          onClick={action.onClick}
          className="mt-4"
        >
          {action.label}
        </Button>
      )}
    </div>
  );
}

// ── Error State ────────────────────────────────────────────────────────────

export interface ErrorStateProps {
  /** The error object or message string. */
  error?: Error | string | null;
  /** Override the default heading. */
  heading?: string;
  /** Retry callback. */
  onRetry?: () => void;
  className?: string;
}

export function ErrorState({
  error,
  heading = "Failed to load",
  onRetry,
  className,
}: ErrorStateProps) {
  const message =
    typeof error === "string"
      ? error
      : error instanceof Error
      ? error.message
      : "An unexpected error occurred.";

  return (
    <div
      className={cn(
        "flex flex-col items-center justify-center py-16 px-6 text-center",
        className
      )}
      role="alert"
    >
      {/* Error icon */}
      <span className="mb-4 text-[#f43f5e]" aria-hidden>
        <svg
          width="32"
          height="32"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
        >
          <circle cx="12" cy="12" r="10" />
          <line x1="12" y1="8" x2="12" y2="12" />
          <line x1="12" y1="16" x2="12.01" y2="16" />
        </svg>
      </span>

      <p className="text-[15px] font-[500] text-[#b5b8c0]">{heading}</p>

      <p className="mt-1 text-[13px] text-[#878c99] font-mono max-w-sm break-all">
        {message}
      </p>

      {onRetry && (
        <Button variant="ghost" size="md" onClick={onRetry} className="mt-4">
          Try again
        </Button>
      )}
    </div>
  );
}

// ── Not Found (404-style) ──────────────────────────────────────────────────

export function NotFound({
  resource = "Resource",
  id,
}: {
  resource?: string;
  id?: string;
}) {
  return (
    <EmptyState
      icon={
        <svg
          width="32"
          height="32"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.5"
        >
          <circle cx="11" cy="11" r="8" />
          <path d="M21 21l-4.35-4.35" />
        </svg>
      }
      heading={`${resource} not found`}
      description={id ? `Could not find ${resource.toLowerCase()} with ID "${id}".` : undefined}
    />
  );
}
