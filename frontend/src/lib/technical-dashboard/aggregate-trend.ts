import type { TechnicalFindingRow } from "@/types";

export interface VulnerabilityTrendPoint { date: string; criticalHigh: number; mediumLow: number; }

export function aggregateVulnerabilityTrend(findings: TechnicalFindingRow[]): VulnerabilityTrendPoint[] {
  const grouped = new Map<string, VulnerabilityTrendPoint>();
  const end = new Date("2026-09-13T00:00:00Z");
  for (let offset = 29; offset >= 0; offset -= 1) {
    const date = new Date(end);
    date.setUTCDate(end.getUTCDate() - offset);
    const key = date.toISOString().slice(0, 10);
    grouped.set(key, { date: key, criticalHigh: 0, mediumLow: 0 });
  }
  findings.forEach((finding) => {
    const date = finding.created_at.slice(0, 10);
    if (!grouped.has(date)) return;
    const point = grouped.get(date) || { date, criticalHigh: 0, mediumLow: 0 };
    if (finding.severity === "critical" || finding.severity === "high") point.criticalHigh += 1;
    if (finding.severity === "medium" || finding.severity === "low") point.mediumLow += 1;
    grouped.set(date, point);
  });
  return Array.from(grouped.values()).sort((left, right) => left.date.localeCompare(right.date));
}
