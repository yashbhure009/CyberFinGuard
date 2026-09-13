import { AppShell } from "@/components/layout/app-shell";
import { TechnicalDashboardSection } from "@/components/technical/technical-dashboard-section";
import { mockUser } from "@/lib/mock-data";

export default function TechnicalDashboardPage() {
  return (
    <AppShell user={mockUser} title="Technical Dashboard" eyebrow="Security operations & risk intelligence">
      <TechnicalDashboardSection />
    </AppShell>
  );
}
