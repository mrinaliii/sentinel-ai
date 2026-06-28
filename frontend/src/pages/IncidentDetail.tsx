/** Incident Detail page stub — Phase 1. */
import { AppShell, PageContent } from "@/components/layout/AppShell";
import { EmptyState } from "@/components/ui/EmptyState";
export default function IncidentDetailPage() {
  return (
    <AppShell header={{ title: "Incident Details", breadcrumb: [{ label: "Incidents" }] }}>
      <PageContent>
        <EmptyState heading="Incident Detail — Phase 6" description="Incident detail with timeline and evidence — Phase 6." />
      </PageContent>
    </AppShell>
  );
}
