/**
 * Dashboard page stub — Phase 1
 * Full implementation in Phase 3.
 */

import { AppShell, PageContent } from "@/components/layout/AppShell";
import { EmptyState } from "@/components/ui/EmptyState";

export default function DashboardPage() {
  return (
    <AppShell header={{ title: "Dashboard" }}>
      <PageContent>
        <EmptyState
          icon={
            <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
              <rect x="3" y="3" width="7" height="7" rx="1" />
              <rect x="14" y="3" width="7" height="7" rx="1" />
              <rect x="3" y="14" width="7" height="7" rx="1" />
              <rect x="14" y="14" width="7" height="7" rx="1" />
            </svg>
          }
          heading="Dashboard — Phase 3"
          description="Dashboard widgets will be implemented in Phase 3."
        />
      </PageContent>
    </AppShell>
  );
}
