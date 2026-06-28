/** MITRE ATT&CK Explorer stub — Phase 1. */
import { AppShell, PageContent } from "@/components/layout/AppShell";
import { EmptyState } from "@/components/ui/EmptyState";
export default function MitrePage() {
  return (
    <AppShell header={{ title: "MITRE ATT&CK Explorer" }}>
      <PageContent>
        <EmptyState heading="MITRE ATT&CK — Phase 7" description="ATT&CK matrix with coverage overlay — Phase 7." />
      </PageContent>
    </AppShell>
  );
}
