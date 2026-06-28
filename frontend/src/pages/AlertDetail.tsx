/** Alert Detail page stub — Phase 1. Full impl in Phase 5. */
import { AppShell, PageContent } from "@/components/layout/AppShell";
import { EmptyState } from "@/components/ui/EmptyState";
export default function AlertDetailPage() {
  return (
    <AppShell header={{ title: "Alert Details", breadcrumb: [{ label: "Alerts" }] }}>
      <PageContent>
        <EmptyState heading="Alert Detail — Phase 5" description="Full alert detail view — Phase 5." />
      </PageContent>
    </AppShell>
  );
}
