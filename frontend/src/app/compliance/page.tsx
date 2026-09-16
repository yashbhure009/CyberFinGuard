import { AppShell } from "@/components/layout/app-shell";
import { ComplianceView } from "@/components/compliance/compliance-view";
import { mockUser } from "@/lib/mock-data";

export default function CompliancePage() {
  return <AppShell user={mockUser} title="Compliance View" eyebrow="Framework coverage & control alignment"><ComplianceView /></AppShell>;
}
