import type { TechnicalFindingRow } from "@/types";

const weights: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
export type EmergingRiskPoint = { date: string; score: number; findingCount: number; severityContribution: number; exploitContribution: number; projected?: boolean };

export function aggregateEmergingRisk(findings: TechnicalFindingRow[]): EmergingRiskPoint[] {
  const latest = findings.reduce((date, finding) => Math.max(date, new Date(finding.created_at).getTime()), 0) || Date.now();
  const start = new Date(latest); start.setUTCDate(start.getUTCDate() - 29);
  const historical = Array.from({ length: 30 }, (_, index) => {
    const day = new Date(start); day.setUTCDate(start.getUTCDate() + index);
    const key = day.toISOString().slice(0, 10);
    const dayFindings = findings.filter((finding) => finding.created_at.slice(0, 10) === key);
    const severityContribution = dayFindings.reduce((sum, finding) => sum + (weights[finding.severity] || 0), 0);
    const exploitContribution = dayFindings.reduce((sum, finding) => sum + (finding.exploit_available || finding.cisa_kev ? 2 : 0), 0);
    return { date: key, score: severityContribution + exploitContribution, findingCount: dayFindings.length, severityContribution, exploitContribution };
  });
  const window = historical.slice(-7);
  const slope = window.length > 1 ? (window[window.length - 1].score - window[0].score) / (window.length - 1) : 0;
  const last = historical[historical.length - 1];
  return [...historical, ...Array.from({ length: 5 }, (_, index) => {
    const day = new Date(`${last.date}T00:00:00Z`); day.setUTCDate(day.getUTCDate() + index + 1);
    const score = Math.max(0, Math.round(last.score + slope * (index + 1)));
    return { date: day.toISOString().slice(0, 10), score, findingCount: 0, severityContribution: 0, exploitContribution: 0, projected: true };
  })];
}
