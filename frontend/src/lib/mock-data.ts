import type { Assessment, CloudIntegration, User } from "@/types";

export const mockUser: User = {
  id: "user-001",
  email: "alex.morgan@bankx.example",
  name: "Alex Morgan",
  role: "CISO",
};

export const mockAssessment: Assessment = {
  id: "assessment-001",
  userId: mockUser.id,
  organizationName: "BankX Financial Services",
  status: "in_progress",
  completedSteps: [],
  createdAt: "2026-09-11T10:00:00.000Z",
  updatedAt: "2026-09-11T10:00:00.000Z",
};

export const cloudCredentialFields: Record<
  CloudIntegration["provider"],
  { key: string; label: string; type: "text" | "password" }[]
> = {
  AWS: [
    { key: "accountId", label: "Account ID", type: "text" },
    { key: "roleArn", label: "Role ARN", type: "text" },
  ],
  Azure: [
    { key: "tenantId", label: "Tenant ID", type: "text" },
    { key: "subscriptionId", label: "Subscription ID", type: "text" },
  ],
  GCP: [
    { key: "projectId", label: "Project ID", type: "text" },
    { key: "serviceAccount", label: "Service account", type: "text" },
  ],
};
