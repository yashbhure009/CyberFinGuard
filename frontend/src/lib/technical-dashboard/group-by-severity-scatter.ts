import type { TechnicalFindingRow } from "@/types";
import { technicalSeverityLevels } from "@/lib/technical-dashboard/severity-config";

export interface CvssEpssPoint { x: number; y: number; findingId: string; }

export function groupBySeverityForScatter(findings: TechnicalFindingRow[]): { key: string; points: CvssEpssPoint[] }[] {
  return technicalSeverityLevels.map((key) => ({ key, points: findings.filter((finding) => finding.severity === key && finding.cvss_score != null && finding.epss_score != null).map((finding) => ({ x: finding.cvss_score as number, y: finding.epss_score as number, findingId: finding.finding_id })), }));
}
