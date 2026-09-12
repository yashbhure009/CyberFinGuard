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

export async function login(email: string, _password: string, role: UserRole): Promise<User> {
  await wait();
  return { ...mockUser, email, role, name: email.split("@")[0].replace(".", " ") };
}

export async function getAssessment(): Promise<Assessment> {
  await wait(150);
  return { ...mockAssessment };
}

export async function saveWebsiteTarget(target: WebsiteTarget): Promise<WebsiteTarget> {
  await wait(650);
  return { ...target, scanStatus: "complete", endpointsAnalyzed: 27, findingsDiscovered: 12, lastScannedAt: new Date().toISOString() };
}

export async function saveNetworkTarget(target: NetworkTarget): Promise<NetworkTarget> {
  await wait();
  return target;
}

export async function saveCloudIntegration(integration: CloudIntegration): Promise<CloudIntegration> {
  await wait();
  return { ...integration, status: "configured" };
}

export async function saveKeycloakIntegration(integration: IAMIntegration): Promise<IAMIntegration> {
  await wait();
  return { ...integration, status: "configured" };
}

export async function saveBusinessContext(context: BusinessContext): Promise<BusinessContext> {
  await wait();
  return context;
}

export async function saveAssessmentProgress(progress: AssessmentProgress): Promise<Assessment> {
  await wait(200);
  return {
    ...mockAssessment,
    completedSteps: Object.values(progress).map((_, index) => index),
    updatedAt: new Date().toISOString(),
  };
}
