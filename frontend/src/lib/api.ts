import { mockAssessment, mockUser } from "@/lib/mock-data";
import type {
  Assessment,
  AssessmentProgress,
  BusinessContext,
  CloudIntegration,
  IAMIntegration,
  NetworkTarget,
  User,
  UserRole,
  WebsiteTarget,
} from "@/types";

const wait = (milliseconds = 450) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const API_BASE_URL = (process.env.NEXT_PUBLIC_API_BASE_URL || "http://localhost:8000").replace(/\/$/, "");

interface AssetResponse {
  assetId: string;
  unmappedFields: string[];
}

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: { "Content-Type": "application/json", ...options?.headers },
  });
  if (!response.ok) {
    const body = await response.json().catch(() => null);
    const detail = body?.detail;
    const message = Array.isArray(detail)
      ? detail.map((issue: { msg?: string }) => issue.msg).filter(Boolean).join(", ")
      : detail;
    throw new Error(message || `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

const postAsset = (path: string, body: unknown) => request<AssetResponse>(path, {
  method: "POST",
  body: JSON.stringify(body),
});

export async function login(email: string, _password: string, role: UserRole): Promise<User> {
  await wait();
  return { ...mockUser, email, role, name: email.split("@")[0].replace(".", " ") };
}

export async function getAssessment(): Promise<Assessment> {
  await wait(150);
  return { ...mockAssessment };
}

export async function saveWebsiteTarget(target: WebsiteTarget): Promise<WebsiteTarget> {
  const asset = await postAsset("/api/assets/website", { url: target.url });
  return { ...target, scanStatus: "complete", assetId: asset.assetId, unmappedFields: asset.unmappedFields };
}

export async function saveNetworkTarget(target: NetworkTarget): Promise<NetworkTarget> {
  const asset = await postAsset("/api/assets/network", target);
  return { ...target, assetId: asset.assetId, unmappedFields: asset.unmappedFields };
}

export async function saveCloudIntegration(integration: CloudIntegration): Promise<CloudIntegration> {
  const asset = await postAsset("/api/assets/cloud", { provider: integration.provider, fields: integration.fields });
  return { ...integration, status: "configured", assetId: asset.assetId, unmappedFields: asset.unmappedFields };
}

export async function saveKeycloakIntegration(integration: IAMIntegration): Promise<IAMIntegration> {
  const asset = await postAsset("/api/assets/iam", {
    url: integration.url,
    realm: integration.realm,
    clientId: integration.clientId,
    clientSecret: integration.clientSecret,
  });
  return {
    url: integration.url,
    realm: integration.realm,
    clientId: integration.clientId,
    status: "configured",
    assetId: asset.assetId,
    unmappedFields: asset.unmappedFields,
  };
}

export async function saveBusinessContext(context: BusinessContext): Promise<BusinessContext> {
  const asset = await postAsset("/api/assets/business-context", context);
  return { ...context, assetId: asset.assetId, unmappedFields: asset.unmappedFields };
}

export async function saveAssessmentProgress(progress: AssessmentProgress): Promise<Assessment> {
  await wait(200);
  return {
    ...mockAssessment,
    completedSteps: Object.values(progress).map((_, index) => index),
    updatedAt: new Date().toISOString(),
  };
}
