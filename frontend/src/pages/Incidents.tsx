/** Incidents page stub — Phase 1. */
import { AppShell, PageContent } from "@/components/layout/AppShell";
import { EmptyState } from "@/components/ui/EmptyState";
export default function IncidentsPage() {
  return (
    <AppShell header={{ title: "Incidents" }}>
      <PageContent>
        <EmptyState heading="Incidents — Phase 6" description="Incident timeline, evidence, and notes — Phase 6." />
      </PageContent>
    </AppShell>
  );
}
