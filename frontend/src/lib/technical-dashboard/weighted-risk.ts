import type { TechnicalFindingRow } from "@/types";

const severityWeights: Record<TechnicalFindingRow["severity"], number> = { critical: 5, high: 4, medium: 2, low: 1 };

// Illustrative weighted score: severity weight × normalized criticality × dependency multiplier.
// Criticality is normalized from the schema's 1–5 scale; dependencies add 10% each.
export function weightedRiskScore(finding: Pick<TechnicalFindingRow, "severity" | "criticality" | "dependencies">): number {
  const normalizedCriticality = Math.min(5, Math.max(1, finding.criticality ?? 1)) / 5;
  const dependencyMultiplier = 1 + 0.1 * (finding.dependencies?.length ?? 0);
  return severityWeights[finding.severity] * normalizedCriticality * dependencyMultiplier;
}
