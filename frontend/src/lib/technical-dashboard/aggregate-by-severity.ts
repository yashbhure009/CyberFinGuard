import type { TechnicalFindingRow } from "@/types";
import { technicalSeverityConfig, technicalSeverityLevels } from "@/lib/technical-dashboard/severity-config";

export function aggregateFindingsBySeverity(findings: TechnicalFindingRow[]) {
  const counts = new Map<string, number>(technicalSeverityLevels.map((severity) => [severity, 0]));
  findings.forEach((finding) => counts.set(finding.severity, (counts.get(finding.severity) || 0) + 1));
  return { total: findings.length, data: technicalSeverityLevels.map((severity) => ({ severity, count: counts.get(severity) || 0, fill: technicalSeverityConfig[severity].color })) };
}
