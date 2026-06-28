/**
 * SentinelAI — Button Component
 *
 * Design spec (DESIGN.md):
 *  - primary: Signal Lime fill (#a8ff53), Ink Well text (#121317), 4px radius
 *  - ghost:   transparent bg, Cloud text (#d7d9dd), hover → Bone text (#e5e7eb)
 *  - danger:  Mute Red border + text (#f43f5e), transparent bg
 *
 * Rules:
 *  - No drop shadows
 *  - No gradients
 *  - Max 4px border radius
 *  - Keyboard accessible (focus-visible ring)
 */

import { forwardRef } from "react";
import type { ButtonHTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────────────────

export type ButtonVariant = "primary" | "ghost" | "danger" | "outline";
export type ButtonSize = "sm" | "md" | "lg";

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  leftIcon?: ReactNode;
  rightIcon?: ReactNode;
}

// ── Styles ─────────────────────────────────────────────────────────────────

const base =
  "inline-flex items-center justify-center gap-1.5 font-medium rounded-[4px] " +
  "transition-colors duration-100 select-none whitespace-nowrap " +
  "disabled:opacity-40 disabled:cursor-not-allowed " +
  "focus-visible:outline focus-visible:outline-1 focus-visible:outline-[#a8ff53] focus-visible:outline-offset-2";

const variants: Record<ButtonVariant, string> = {
  primary:
    "bg-[#a8ff53] text-[#121317] hover:bg-[#b8ff6e] active:bg-[#98ee43] " +
    "font-[500]",
  ghost:
    "bg-transparent text-[#d7d9dd] hover:text-[#e5e7eb] hover:bg-[rgba(255,255,255,0.04)] " +
    "active:bg-[rgba(255,255,255,0.07)]",
  danger:
    "bg-transparent text-[#f43f5e] border border-[#f43f5e] " +
    "hover:bg-[rgba(244,63,94,0.08)] active:bg-[rgba(244,63,94,0.12)]",
  outline:
    "bg-transparent text-[#d7d9dd] border border-[#3b3e45] " +
    "hover:border-[#878c99] hover:text-[#e5e7eb] active:bg-[rgba(255,255,255,0.04)]",
};

const sizes: Record<ButtonSize, string> = {
  sm: "text-[13px] leading-[1.43] px-3 py-1.5 h-7",
  md: "text-[14px] leading-[1.43] px-4 py-2 h-8",
  lg: "text-[14px] leading-[1.43] px-5 py-2.5 h-9",
};

// ── Component ──────────────────────────────────────────────────────────────

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = "ghost",
      size = "md",
      loading = false,
      leftIcon,
      rightIcon,
      className,
      disabled,
      children,
      ...props
    },
    ref
  ) => {
    return (
      <button
        ref={ref}
        className={cn(base, variants[variant], sizes[size], className)}
        disabled={disabled || loading}
        aria-busy={loading}
        {...props}
      >
        {loading ? (
          <span className="inline-block h-3.5 w-3.5 animate-spin rounded-full border border-current border-t-transparent" />
        ) : (
          leftIcon && <span className="flex-shrink-0">{leftIcon}</span>
        )}
        {children}
        {!loading && rightIcon && <span className="flex-shrink-0">{rightIcon}</span>}
      </button>
    );
  }
);

Button.displayName = "Button";
