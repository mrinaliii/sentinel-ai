/**
 * SentinelAI — Input & Select Components
 *
 * Design spec (DESIGN.md):
 *  - Background: #121317 (Ink Well)
 *  - Border: #272a2e (Steel Border), focus → #3b3e45 (Graphite Hairline)
 *  - Text: #e5e7eb (Bone Text)
 *  - Placeholder: #878c99 (Fog Text)
 *  - Border radius: 4px
 *  - No drop shadows
 *  - Focus ring: 1px #a8ff53 outline-offset-2
 */

import { forwardRef } from "react";
import type { InputHTMLAttributes, SelectHTMLAttributes, TextareaHTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/utils";

// ── Shared base classes ────────────────────────────────────────────────────

const inputBase =
  "w-full rounded-[4px] border border-[#272a2e] bg-[#121317] text-[#e5e7eb] " +
  "text-[14px] leading-[1.43] font-[family-name:var(--font-geist)] " +
  "placeholder:text-[#878c99] " +
  "transition-colors duration-100 " +
  "hover:border-[#3b3e45] " +
  "focus:outline-none focus:border-[#3b3e45] focus:ring-1 focus:ring-[#a8ff53] focus:ring-offset-0 " +
  "disabled:opacity-40 disabled:cursor-not-allowed";

// ── Text Input ─────────────────────────────────────────────────────────────

export interface InputProps extends InputHTMLAttributes<HTMLInputElement> {
  leftIcon?: ReactNode;
  rightIcon?: ReactNode;
  label?: string;
  hint?: string;
  error?: string;
  inputClassName?: string;
}

export const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ leftIcon, rightIcon, label, hint, error, className, inputClassName, id, ...props }, ref) => {
    const inputId = id ?? label?.toLowerCase().replace(/\s+/g, "-");

    return (
      <div className={cn("flex flex-col gap-1", className)}>
        {label && (
          <label
            htmlFor={inputId}
            className="text-[13px] text-[#b5b8c0] font-[family-name:var(--font-geist)]"
          >
            {label}
          </label>
        )}

        <div className="relative flex items-center">
          {leftIcon && (
            <span className="pointer-events-none absolute left-3 text-[#878c99] flex items-center">
              {leftIcon}
            </span>
          )}

          <input
            ref={ref}
            id={inputId}
            className={cn(
              inputBase,
              "py-1.5 px-3 h-8",
              leftIcon && "pl-8",
              rightIcon && "pr-8",
              error && "border-[#f43f5e] focus:ring-[#f43f5e]",
              inputClassName
            )}
            aria-invalid={!!error}
            aria-describedby={error ? `${inputId}-error` : hint ? `${inputId}-hint` : undefined}
            {...props}
          />

          {rightIcon && (
            <span className="absolute right-3 text-[#878c99] flex items-center">
              {rightIcon}
            </span>
          )}
        </div>

        {error && (
          <p id={`${inputId}-error`} className="text-[12px] text-[#f43f5e]" role="alert">
            {error}
          </p>
        )}

        {!error && hint && (
          <p id={`${inputId}-hint`} className="text-[12px] text-[#878c99]">
            {hint}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = "Input";

// ── Textarea ───────────────────────────────────────────────────────────────

export interface TextareaProps extends TextareaHTMLAttributes<HTMLTextAreaElement> {
  label?: string;
  hint?: string;
  error?: string;
}

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaProps>(
  ({ label, hint, error, className, id, ...props }, ref) => {
    const inputId = id ?? label?.toLowerCase().replace(/\s+/g, "-");

    return (
      <div className={cn("flex flex-col gap-1", className)}>
        {label && (
          <label
            htmlFor={inputId}
            className="text-[13px] text-[#b5b8c0]"
          >
            {label}
          </label>
        )}

        <textarea
          ref={ref}
          id={inputId}
          className={cn(
            inputBase,
            "py-2 px-3 resize-y min-h-[80px]",
            error && "border-[#f43f5e] focus:ring-[#f43f5e]"
          )}
          aria-invalid={!!error}
          {...props}
        />

        {error && (
          <p className="text-[12px] text-[#f43f5e]" role="alert">
            {error}
          </p>
        )}

        {!error && hint && (
          <p className="text-[12px] text-[#878c99]">{hint}</p>
        )}
      </div>
    );
  }
);

Textarea.displayName = "Textarea";

// ── Select ─────────────────────────────────────────────────────────────────

export interface SelectProps extends SelectHTMLAttributes<HTMLSelectElement> {
  label?: string;
  hint?: string;
  error?: string;
}

export const Select = forwardRef<HTMLSelectElement, SelectProps>(
  ({ label, hint, error, className, id, children, ...props }, ref) => {
    const inputId = id ?? label?.toLowerCase().replace(/\s+/g, "-");

    return (
      <div className={cn("flex flex-col gap-1", className)}>
        {label && (
          <label htmlFor={inputId} className="text-[13px] text-[#b5b8c0]">
            {label}
          </label>
        )}

        <select
          ref={ref}
          id={inputId}
          className={cn(
            inputBase,
            "py-1.5 px-3 h-8 pr-8 appearance-none cursor-pointer",
            "bg-[image:url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23878c99' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E\")] bg-no-repeat bg-[right_0.5rem_center]",
            error && "border-[#f43f5e]"
          )}
          aria-invalid={!!error}
          {...props}
        >
          {children}
        </select>

        {error && (
          <p className="text-[12px] text-[#f43f5e]" role="alert">
            {error}
          </p>
        )}

        {!error && hint && <p className="text-[12px] text-[#878c99]">{hint}</p>}
      </div>
    );
  }
);

Select.displayName = "Select";

// ── Search Input (shortcut convenience) ───────────────────────────────────

export interface SearchInputProps extends Omit<InputProps, "leftIcon" | "type"> {
  onClear?: () => void;
}

export function SearchInput({ onClear, value, className, ...props }: SearchInputProps) {
  return (
    <Input
      type="search"
      value={value}
      className={className}
      leftIcon={
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="11" cy="11" r="8" />
          <path d="M21 21l-4.35-4.35" />
        </svg>
      }
      rightIcon={
        value && onClear ? (
          <button
            type="button"
            onClick={onClear}
            className="text-[#878c99] hover:text-[#e5e7eb] transition-colors"
            aria-label="Clear search"
          >
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <path d="M18 6L6 18M6 6l12 12" />
            </svg>
          </button>
        ) : undefined
      }
      {...props}
    />
  );
}
