/** Analyst Copilot page stub — Phase 1. */
import { AppShell, PageContent } from "@/components/layout/AppShell";
import { EmptyState } from "@/components/ui/EmptyState";
export default function CopilotPage() {
  return (
    <AppShell header={{ title: "Analyst Copilot" }}>
      <PageContent>
        <EmptyState heading="Analyst Copilot — Phase 8" description="AI-powered chat interface with context panel — Phase 8." />
      </PageContent>
    </AppShell>
  );
}
