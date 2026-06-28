/**
 * SentinelAI — Card Component
 *
 * Design spec (DESIGN.md):
 *  - Background: #1c1e21 (Slate Canvas / Card surface)
 *  - Border: 1px #272a2e (Steel Border)
 *  - Hover border: #3b3e45 (Graphite Hairline)
 *  - Border radius: 4px
 *  - No drop shadows
 *  - Padding: 24px (card-padding spec)
 */

import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/utils";

// ── Card ───────────────────────────────────────────────────────────────────

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  /** Removes the default padding for layouts that need full-bleed content. */
  noPadding?: boolean;
  /** Makes the card surface inset (uses #121317 instead of canvas). */
  inset?: boolean;
  /** Adds a hover border-color transition. */
  hoverable?: boolean;
}

export function Card({
  noPadding,
  inset,
  hoverable,
  className,
  children,
  ...props
}: CardProps) {
  return (
    <div
      className={cn(
        "rounded-[4px] border border-[#272a2e]",
        inset ? "bg-[#121317]" : "bg-[#1c1e21]",
        !noPadding && "p-6",
        hoverable && "transition-colors duration-100 hover:border-[#3b3e45] cursor-pointer",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

// ── Card sub-components ────────────────────────────────────────────────────

export function CardHeader({
  className,
  children,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "flex items-center justify-between gap-3 pb-4 border-b border-[#272a2e] mb-4",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

export function CardTitle({
  className,
  children,
  ...props
}: HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3
      className={cn(
        "font-[family-name:var(--font-satoshi)] font-[500] text-[16px] text-[#e5e7eb]",
        className
      )}
      {...props}
    >
      {children}
    </h3>
  );
}

export function CardBody({
  className,
  children,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("", className)} {...props}>
      {children}
    </div>
  );
}

export function CardFooter({
  className,
  children,
  ...props
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "pt-4 mt-4 border-t border-[#272a2e] flex items-center gap-3",
        className
      )}
      {...props}
    >
      {children}
    </div>
  );
}

// ── Section (labeled group within a card) ─────────────────────────────────

export function Section({
  title,
  action,
  children,
  className,
}: {
  title?: string;
  action?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={cn("", className)}>
      {(title || action) && (
        <div className="flex items-center justify-between gap-3 mb-3">
          {title && (
            <span className="text-[13px] font-[500] text-[#878c99] uppercase tracking-wider">
              {title}
            </span>
          )}
          {action}
        </div>
      )}
      {children}
    </section>
  );
}
