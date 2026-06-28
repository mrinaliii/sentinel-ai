/**
 * SentinelAI — AppShell
 *
 * Root layout component that composes Sidebar + Header + main content area.
 *
 * Layout:
 *  - Full viewport height (100dvh)
 *  - Sidebar: 260px fixed left column (Ink Well)
 *  - Main: remaining width, flex column
 *  - Header: 48px sticky top bar
 *  - Content: scrollable area
 *
 * Mobile (< lg):
 *  - Sidebar hidden off-screen, toggled via hamburger
 *  - Main takes full width
 */

import { useState } from "react";
import type { ReactNode } from "react";
import { Sidebar } from "./Sidebar";
import { Header } from "./Header";
import type { HeaderProps } from "./Header";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────────────────

export interface AppShellProps {
  /** Props forwarded to the Header component. */
  header: Omit<HeaderProps, "onMenuClick">;
  /** Page content rendered inside the scrollable main area. */
  children: ReactNode;
  /** Optional class applied to the content wrapper. */
  contentClassName?: string;
}

// ── Component ──────────────────────────────────────────────────────────────

export function AppShell({ header, children, contentClassName }: AppShellProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="flex h-dvh overflow-hidden bg-[#1c1e21]">
      {/* Sidebar */}
      <Sidebar
        open={sidebarOpen}
        onClose={() => setSidebarOpen(false)}
      />

      {/* Main column */}
      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        {/* Header */}
        <Header
          {...header}
          onMenuClick={() => setSidebarOpen(true)}
        />

        {/* Scrollable content */}
        <main
          id="main-content"
          className={cn(
            "flex-1 overflow-y-auto overflow-x-hidden",
            "bg-[#1c1e21]",
            contentClassName
          )}
          tabIndex={-1}
          aria-label="Page content"
        >
          {children}
        </main>
      </div>
    </div>
  );
}

// ── Page content wrapper (standard padding) ────────────────────────────────

export function PageContent({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("p-6 max-w-[1440px] mx-auto", className)}>
      {children}
    </div>
  );
}
