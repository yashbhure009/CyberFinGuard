import type { MitigationRecommendation, RiskQuantificationSummary } from "@/types";

// Demo records standing in for risk_scores until the risk engine populates the real table.
export const riskSummary: RiskQuantificationSummary = {
  asset_name: "Payment Gateway", criticality: 5, asset_value: 50000000, business_unit: "Digital Banking",
  likelihood_score: 0.72, impact_score: 0.91, sle: 12500000, aro: 0.34, ale: 4250000,
};

// risk_reduction is a percentage of ALE, consistently across these demo records.
export const mitigationRecommendations: MitigationRecommendation[] = [
  { recommendation_id: "REC-001", asset_id: "AST-001", control_name: "patch deployment", investment_cost: 450000, risk_reduction: 32, roi: 3.4, priority: 1 },
  { recommendation_id: "REC-002", asset_id: "AST-001", control_name: "access control tightening", investment_cost: 280000, risk_reduction: 24, roi: 3.1, priority: 2 },
  { recommendation_id: "REC-003", asset_id: "AST-002", control_name: "network segmentation", investment_cost: 650000, risk_reduction: 21, roi: 2.2, priority: 3 },
  { recommendation_id: "REC-004", asset_id: "AST-003", control_name: "additional monitoring", investment_cost: 175000, risk_reduction: 12, roi: 2.9, priority: 4 },
  { recommendation_id: "REC-005", asset_id: "AST-004", control_name: "patch deployment", investment_cost: 120000, risk_reduction: 9, roi: 2.6, priority: 5 },
  { recommendation_id: "REC-006", asset_id: "AST-005", control_name: "access control tightening", investment_cost: 210000, risk_reduction: 8, roi: 1.9, priority: 5 },
];

// Illustrative 95th-percentile-style tail-loss estimate; this is not an actuarial VaR calculation.
export function estimateValueAtRisk(ale?: number | null): number | undefined {
  return ale == null ? undefined : Math.round(ale * 1.8);
}
