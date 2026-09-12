export type UserRole = "CISO" | "CFO";

export interface User {
  id: string;
  email: string;
  name: string;
  role: UserRole;
}

export type AssessmentStatus = "draft" | "in_progress" | "ready" | "analyzing" | "complete";

export interface Assessment {
  id: string;
  userId: string;
  organizationName: string;
  status: AssessmentStatus;
  completedSteps: number[];
  createdAt: string;
  updatedAt: string;
}

export interface WebsiteTarget {
  url: string;
  scanStatus: "idle" | "scanning" | "complete" | "failed";
  endpointsAnalyzed?: number;
  findingsDiscovered?: number;
  lastScannedAt?: string;
  assetId?: string;
  unmappedFields?: string[];
}

export interface NetworkTarget {
  ipAddress: string;
  port: number;
  assetId?: string;
  unmappedFields?: string[];
}

export type CloudProvider = "AWS" | "Azure" | "GCP";

export interface CloudIntegration {
  provider: CloudProvider;
  fields: Record<string, string>;
  status: "configured" | "pending";
  assetId?: string;
  unmappedFields?: string[];
}

export interface IAMIntegration {
  url: string;
  realm: string;
  clientId: string;
  status: "configured" | "pending";
  clientSecret?: string;
  assetId?: string;
  unmappedFields?: string[];
}

export interface BusinessContext {
  assetName: string;
  assetType: string;
  businessUnit: string;
  assetOwner: string;
  businessValue: number;
  operationalCriticality: number;
  dataSensitivity: string;
  serviceDependency: string;
  downtimeCostPerHour: number;
  regulatoryExposure: number;
  recoveryCost: number;
  revenueDependency: number;
  assetCriticality: number;
  assetId?: string;
  unmappedFields?: string[];
}

export interface AssessmentProgress {
  website?: WebsiteTarget;
  network?: NetworkTarget;
  cloud?: CloudIntegration;
  iam?: IAMIntegration;
  business?: BusinessContext;
}
