/** Alerts page stub — Phase 1. Full impl in Phase 4. */
import { AppShell, PageContent } from "@/components/layout/AppShell";
import { EmptyState } from "@/components/ui/EmptyState";
export default function AlertsPage() {
  return (
    <AppShell header={{ title: "Alerts" }}>
      <PageContent>
        <EmptyState heading="Alerts — Phase 4" description="Alerts table with search, filters, and bulk actions — Phase 4." />
      </PageContent>
    </AppShell>
  );
}
