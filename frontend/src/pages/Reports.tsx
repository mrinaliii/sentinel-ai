/** Reports page stub — Phase 1. */
import { AppShell, PageContent } from "@/components/layout/AppShell";
import { EmptyState } from "@/components/ui/EmptyState";
export default function ReportsPage() {
  return (
    <AppShell header={{ title: "Reports" }}>
      <PageContent>
        <EmptyState heading="Reports — Phase 9" description="SOC incident report list and viewer — Phase 9." />
      </PageContent>
    </AppShell>
  );
}
