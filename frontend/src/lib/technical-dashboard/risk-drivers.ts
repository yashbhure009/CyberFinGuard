import type { TechnicalFindingRow } from "@/types";

export function getRiskDrivers(finding: TechnicalFindingRow): string[] {
  const drivers: string[] = [];
  if (finding.severity === "critical" || finding.severity === "high") drivers.push(`${finding.severity} severity finding`);
  if (finding.exploit_available || finding.cisa_kev) drivers.push("Known exploit activity");
  if (finding.patching_status === "unpatched") drivers.push("Unpatched exposure");
  if (finding.internet_exposed) drivers.push("Internet-exposed asset");
  if (!finding.mfa_enabled) drivers.push("MFA coverage gap");
  if (!finding.edr_enabled) drivers.push("EDR coverage gap");
  return drivers;
}
