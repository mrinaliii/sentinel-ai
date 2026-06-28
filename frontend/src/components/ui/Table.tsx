/**
 * SentinelAI — Table Component
 *
 * Dense, sortable data table primitives.
 *
 * Design spec (DESIGN.md — Alert Table):
 *  - Row height: 48px
 *  - Hover: border-color → #3b3e45
 *  - Selected row: background #121317
 *  - Column headers: 13px Geist 500, #878c99 uppercase
 *  - Cell text: 14px Geist 400, #e5e7eb
 *
 * This file provides primitive building blocks (Table, THead, TBody, Tr, Th, Td).
 * Feature pages compose these with their own columns.
 */

import type { HTMLAttributes, ReactNode, ThHTMLAttributes, TdHTMLAttributes } from "react";
import { cn } from "@/lib/utils";

// ── Table wrapper ──────────────────────────────────────────────────────────

export interface TableProps extends HTMLAttributes<HTMLDivElement> {
  /** Adds a fixed min-width for horizontal scroll on small viewports. */
  minWidth?: number;
}

export function Table({ minWidth, className, children, ...props }: TableProps) {
  return (
    <div className="overflow-x-auto w-full" {...props}>
      <table
        className={cn("w-full border-collapse", className)}
        style={minWidth ? { minWidth } : undefined}
        role="table"
      >
        {children}
      </table>
    </div>
  );
}

// ── THead ──────────────────────────────────────────────────────────────────

export function THead({ className, children, ...props }: HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <thead
      className={cn("border-b border-[#272a2e]", className)}
      {...props}
    >
      {children}
    </thead>
  );
}

// ── TBody ──────────────────────────────────────────────────────────────────

export function TBody({ className, children, ...props }: HTMLAttributes<HTMLTableSectionElement>) {
  return (
    <tbody className={cn("divide-y divide-[#1e2124]", className)} {...props}>
      {children}
    </tbody>
  );
}

// ── Tr ─────────────────────────────────────────────────────────────────────

export interface TrProps extends HTMLAttributes<HTMLTableRowElement> {
  selected?: boolean;
  hoverable?: boolean;
  clickable?: boolean;
}

export function Tr({ selected, hoverable = true, clickable, className, children, ...props }: TrProps) {
  return (
    <tr
      className={cn(
        "h-12 group transition-colors duration-75",
        selected ? "bg-[#121317]" : "bg-transparent",
        hoverable && !selected && "hover:bg-[rgba(255,255,255,0.02)]",
        clickable && "cursor-pointer",
        className
      )}
      aria-selected={selected}
      {...props}
    >
      {children}
    </tr>
  );
}

// ── Th ─────────────────────────────────────────────────────────────────────

export type SortDirection = "asc" | "desc" | false;

export interface ThProps extends ThHTMLAttributes<HTMLTableCellElement> {
  sortable?: boolean;
  sortDirection?: SortDirection;
  onSort?: () => void;
}

export function Th({ sortable, sortDirection, onSort, className, children, ...props }: ThProps) {
  return (
    <th
      className={cn(
        "px-3 py-2 text-left text-[12px] font-[500] text-[#878c99] uppercase tracking-wider",
        "font-[family-name:var(--font-geist)] whitespace-nowrap select-none",
        sortable && "cursor-pointer hover:text-[#b5b8c0] transition-colors",
        className
      )}
      onClick={sortable ? onSort : undefined}
      aria-sort={
        sortDirection === "asc"
          ? "ascending"
          : sortDirection === "desc"
          ? "descending"
          : sortable
          ? "none"
          : undefined
      }
      role={sortable ? "columnheader" : undefined}
      {...props}
    >
      <span className="inline-flex items-center gap-1">
        {children}
        {sortable && (
          <SortIcon direction={sortDirection ?? false} />
        )}
      </span>
    </th>
  );
}

// ── Sort icon ──────────────────────────────────────────────────────────────

function SortIcon({ direction }: { direction: SortDirection }) {
  return (
    <span className="inline-flex flex-col gap-0.5 opacity-60" aria-hidden>
      <svg
        width="8"
        height="5"
        viewBox="0 0 8 5"
        fill="none"
        className={cn(direction === "asc" ? "opacity-100 text-[#a8ff53]" : "opacity-40")}
      >
        <path d="M4 0L7.46 4H0.54L4 0Z" fill="currentColor" />
      </svg>
      <svg
        width="8"
        height="5"
        viewBox="0 0 8 5"
        fill="none"
        className={cn(direction === "desc" ? "opacity-100 text-[#a8ff53]" : "opacity-40")}
      >
        <path d="M4 5L0.54 1H7.46L4 5Z" fill="currentColor" />
      </svg>
    </span>
  );
}

// ── Td ─────────────────────────────────────────────────────────────────────

export function Td({ className, children, ...props }: TdHTMLAttributes<HTMLTableCellElement>) {
  return (
    <td
      className={cn(
        "px-3 py-2 text-[14px] text-[#e5e7eb] font-[family-name:var(--font-geist)]",
        "whitespace-nowrap",
        className
      )}
      {...props}
    >
      {children}
    </td>
  );
}

// ── TableCheckbox (for bulk-select rows) ──────────────────────────────────

export function TableCheckbox({
  checked,
  indeterminate,
  onChange,
  label,
}: {
  checked: boolean;
  indeterminate?: boolean;
  onChange: (checked: boolean) => void;
  label: string;
}) {
  return (
    <td className="px-3 py-2 w-10">
      <input
        type="checkbox"
        checked={checked}
        ref={(el) => {
          if (el) el.indeterminate = !!indeterminate;
        }}
        onChange={(e) => onChange(e.target.checked)}
        aria-label={label}
        className={cn(
          "h-3.5 w-3.5 rounded-[2px] border border-[#3b3e45] bg-[#121317]",
          "checked:bg-[#a8ff53] checked:border-[#a8ff53]",
          "focus:ring-1 focus:ring-[#a8ff53] focus:ring-offset-0",
          "cursor-pointer accent-[#a8ff53]"
        )}
      />
    </td>
  );
}

// ── Empty table row ────────────────────────────────────────────────────────

export function TableEmpty({
  colSpan,
  message = "No data",
}: {
  colSpan: number;
  message?: ReactNode;
}) {
  return (
    <tr>
      <td
        colSpan={colSpan}
        className="py-16 text-center text-[14px] text-[#878c99]"
      >
        {message}
      </td>
    </tr>
  );
}
