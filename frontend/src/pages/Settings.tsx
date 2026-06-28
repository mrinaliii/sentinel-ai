/** Settings page stub — Phase 1. */
import { AppShell, PageContent } from "@/components/layout/AppShell";
import { EmptyState } from "@/components/ui/EmptyState";
export default function SettingsPage() {
  return (
    <AppShell header={{ title: "Settings" }}>
      <PageContent>
        <EmptyState heading="Settings — Phase 10" description="Profile, integrations, API keys — Phase 10." />
      </PageContent>
    </AppShell>
  );
}
