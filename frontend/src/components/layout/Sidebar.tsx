/**
 * SentinelAI — Sidebar Navigation
 *
 * Design spec (DESIGN.md — Sidebar):
 *  - Width: 260px
 *  - Background: #121317 (Ink Well)
 *  - Right border: 1px #272a2e
 *  - Active item: bg rgba(168,255,83,0.08), text #a8ff53
 *  - Active icon: #a8ff53
 *  - Inactive text: #878c99 (fog)
 *  - Logo mark: lime (#a8ff53)
 *
 * Rules:
 *  - No drop shadows
 *  - Keyboard navigable (role="navigation", aria-current)
 *  - Collapsible on mobile via Zustand UI state
 */

import { NavLink, useLocation } from "react-router-dom";
import { cn } from "@/lib/utils";

// ── Nav items ──────────────────────────────────────────────────────────────

interface NavItem {
  label: string;
  href: string;
  icon: React.ReactNode;
}

const NAV_ITEMS: NavItem[] = [
  {
    label: "Dashboard",
    href: "/",
    icon: <DashboardIcon />,
  },
  {
    label: "Alerts",
    href: "/alerts",
    icon: <AlertIcon />,
  },
  {
    label: "Incidents",
    href: "/incidents",
    icon: <IncidentIcon />,
  },
  {
    label: "MITRE ATT&CK",
    href: "/mitre",
    icon: <MitreIcon />,
  },
  {
    label: "Analyst Copilot",
    href: "/copilot",
    icon: <CopilotIcon />,
  },
  {
    label: "Reports",
    href: "/reports",
    icon: <ReportIcon />,
  },
];

const BOTTOM_ITEMS: NavItem[] = [
  {
    label: "Settings",
    href: "/settings",
    icon: <SettingsIcon />,
  },
];

// ── Component ──────────────────────────────────────────────────────────────

interface SidebarProps {
  /** For mobile: controlled open state. */
  open?: boolean;
  onClose?: () => void;
}

export function Sidebar({ open, onClose }: SidebarProps) {
  const location = useLocation();

  return (
    <>
      {/* Mobile backdrop */}
      {open !== undefined && (
        <div
          className={cn(
            "fixed inset-0 z-30 bg-black/60 lg:hidden",
            open ? "block" : "hidden"
          )}
          onClick={onClose}
          aria-hidden
        />
      )}

      {/* Sidebar panel */}
      <aside
        id="sidebar"
        aria-label="Main navigation"
        className={cn(
          "fixed left-0 top-0 bottom-0 z-40",
          "w-[260px] bg-[#121317] border-r border-[#272a2e]",
          "flex flex-col",
          // Mobile: slide in/out
          "transition-transform duration-200 ease-in-out",
          "lg:translate-x-0 lg:static lg:z-auto",
          open === false && "-translate-x-full"
        )}
      >
        {/* Logo */}
        <div className="flex items-center gap-2.5 px-5 py-4 border-b border-[#272a2e] flex-shrink-0">
          {/* Signal lime mark */}
          <svg width="22" height="22" viewBox="0 0 22 22" fill="none" aria-hidden>
            <path
              d="M11 2L20 7V15L11 20L2 15V7L11 2Z"
              fill="#a8ff53"
              fillOpacity="0.15"
              stroke="#a8ff53"
              strokeWidth="1.5"
            />
            <path d="M11 6L16 9V13L11 16L6 13V9L11 6Z" fill="#a8ff53" />
          </svg>
          <span className="font-[family-name:var(--font-satoshi)] font-[600] text-[16px] text-[#e5e7eb] tracking-tight">
            Sentinel<span className="text-[#a8ff53]">AI</span>
          </span>
        </div>

        {/* Primary nav */}
        <nav
          role="navigation"
          aria-label="Primary navigation"
          className="flex-1 py-3 overflow-y-auto"
        >
          <ul role="list" className="space-y-0.5 px-2">
            {NAV_ITEMS.map((item) => (
              <li key={item.href}>
                <SidebarNavLink
                  item={item}
                  active={
                    item.href === "/"
                      ? location.pathname === "/"
                      : location.pathname.startsWith(item.href)
                  }
                  onClick={onClose}
                />
              </li>
            ))}
          </ul>
        </nav>

        {/* Bottom: settings + user */}
        <div className="py-3 border-t border-[#272a2e]">
          <ul role="list" className="space-y-0.5 px-2">
            {BOTTOM_ITEMS.map((item) => (
              <li key={item.href}>
                <SidebarNavLink
                  item={item}
                  active={location.pathname.startsWith(item.href)}
                  onClick={onClose}
                />
              </li>
            ))}
          </ul>

          {/* User chip */}
          <div className="mx-2 mt-2 flex items-center gap-2.5 rounded-[4px] border border-[#272a2e] bg-[#1c1e21] px-3 py-2">
            <span
              className="flex h-6 w-6 items-center justify-center rounded-full bg-[#a8ff53] text-[#121317] text-[11px] font-[700] flex-shrink-0"
              aria-hidden
            >
              SA
            </span>
            <div className="min-w-0">
              <p className="text-[13px] text-[#e5e7eb] truncate">SOC Analyst</p>
              <p className="text-[11px] text-[#878c99] truncate">analyst@acme.com</p>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
}

// ── Nav Link Item ──────────────────────────────────────────────────────────

function SidebarNavLink({
  item,
  active,
  onClick,
}: {
  item: NavItem;
  active: boolean;
  onClick?: () => void;
}) {
  return (
    <NavLink
      to={item.href}
      onClick={onClick}
      aria-current={active ? "page" : undefined}
      className={cn(
        "flex items-center gap-2.5 rounded-[4px] px-3 py-2",
        "text-[14px] font-[family-name:var(--font-geist)]",
        "transition-colors duration-75 outline-none",
        "focus-visible:ring-1 focus-visible:ring-[#a8ff53]",
        active
          ? "bg-[rgba(168,255,83,0.08)] text-[#a8ff53]"
          : "text-[#878c99] hover:text-[#d7d9dd] hover:bg-[rgba(255,255,255,0.04)]"
      )}
    >
      <span
        className={cn("flex-shrink-0 h-4 w-4", active ? "text-[#a8ff53]" : "text-[#878c99]")}
        aria-hidden
      >
        {item.icon}
      </span>
      {item.label}
    </NavLink>
  );
}

// ── Icons (inline SVGs, 16×16) ─────────────────────────────────────────────

function DashboardIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="1" y="1" width="6" height="6" rx="1" />
      <rect x="9" y="1" width="6" height="6" rx="1" />
      <rect x="1" y="9" width="6" height="6" rx="1" />
      <rect x="9" y="9" width="6" height="6" rx="1" />
    </svg>
  );
}

function AlertIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M8 1L15 13H1L8 1Z" />
      <path d="M8 6V9" strokeLinecap="round" />
      <circle cx="8" cy="11.5" r="0.5" fill="currentColor" />
    </svg>
  );
}

function IncidentIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="8" cy="8" r="7" />
      <path d="M8 5V8" strokeLinecap="round" />
      <circle cx="8" cy="11" r="0.5" fill="currentColor" />
    </svg>
  );
}

function MitreIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <rect x="1" y="1" width="4" height="4" rx="0.5" />
      <rect x="6" y="1" width="4" height="4" rx="0.5" />
      <rect x="11" y="1" width="4" height="4" rx="0.5" />
      <rect x="1" y="6" width="4" height="4" rx="0.5" />
      <rect x="6" y="6" width="4" height="4" rx="0.5" />
      <rect x="11" y="11" width="4" height="4" rx="0.5" />
    </svg>
  );
}

function CopilotIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M14 10.5C14 11.6 13.1 12.5 12 12.5H5L2 15V4.5C2 3.4 2.9 2.5 4 2.5H12C13.1 2.5 14 3.4 14 4.5V10.5Z" />
      <path d="M5.5 7H10.5" strokeLinecap="round" />
      <path d="M5.5 9.5H8.5" strokeLinecap="round" />
    </svg>
  );
}

function ReportIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <path d="M3 2H10L13 5V14H3V2Z" />
      <path d="M10 2V5H13" />
      <path d="M5.5 8H10.5" strokeLinecap="round" />
      <path d="M5.5 10.5H9" strokeLinecap="round" />
    </svg>
  );
}

function SettingsIcon() {
  return (
    <svg viewBox="0 0 16 16" fill="none" stroke="currentColor" strokeWidth="1.5">
      <circle cx="8" cy="8" r="2.5" />
      <path d="M8 1v2M8 13v2M1 8h2M13 8h2M3.22 3.22l1.41 1.41M11.37 11.37l1.41 1.41M3.22 12.78l1.41-1.41M11.37 4.63l1.41-1.41" strokeLinecap="round" />
    </svg>
  );
}
