/**
 * SentinelAI — Application Router
 *
 * Defines all client-side routes using React Router v7.
 * Pages are lazy-loaded for code-splitting.
 * Phase 1: stub pages only. Feature pages added in subsequent phases.
 */

import { lazy, Suspense } from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { PageSpinner } from "@/components/ui/Spinner";

// ── Lazy page imports ──────────────────────────────────────────────────────

const DashboardPage = lazy(() => import("@/pages/Dashboard"));
const AlertsPage = lazy(() => import("@/pages/Alerts"));
const AlertDetailPage = lazy(() => import("@/pages/AlertDetail"));
const IncidentsPage = lazy(() => import("@/pages/Incidents"));
const IncidentDetailPage = lazy(() => import("@/pages/IncidentDetail"));
const MitrePage = lazy(() => import("@/pages/Mitre"));
const CopilotPage = lazy(() => import("@/pages/Copilot"));
const ReportsPage = lazy(() => import("@/pages/Reports"));
const SettingsPage = lazy(() => import("@/pages/Settings"));

// ── Router ─────────────────────────────────────────────────────────────────

export function AppRouter() {
  return (
    <Suspense fallback={<PageSpinner label="Loading page…" />}>
      <Routes>
        <Route path="/" element={<DashboardPage />} />
        <Route path="/alerts" element={<AlertsPage />} />
        <Route path="/alerts/:alertId" element={<AlertDetailPage />} />
        <Route path="/incidents" element={<IncidentsPage />} />
        <Route path="/incidents/:incidentId" element={<IncidentDetailPage />} />
        <Route path="/mitre" element={<MitrePage />} />
        <Route path="/copilot" element={<CopilotPage />} />
        <Route path="/reports" element={<ReportsPage />} />
        <Route path="/settings" element={<SettingsPage />} />
        {/* Catch-all redirect */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </Suspense>
  );
}
