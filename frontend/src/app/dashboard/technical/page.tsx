import { AppShell } from "@/components/layout/app-shell";
import { TechnicalDashboardLive } from "@/components/technical/technical-dashboard-live";
import { mockUser } from "@/lib/mock-data";

export default function TechnicalDashboardPage() {
  return (
    <AppShell user={mockUser} title="Technical Dashboard" eyebrow="Security operations & risk intelligence">
      <TechnicalDashboardLive />
    </AppShell>
  );
}
