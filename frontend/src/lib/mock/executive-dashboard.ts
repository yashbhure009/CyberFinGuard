import type { AssetFinancialExposure, MitigationRecommendation } from "@/types";

// Demo financial exposure records standing in for risk_scores until the risk engine is populated.
// The first five assets intentionally match the existing technical/risk-analysis demo records.
export const assetFinancialExposures: AssetFinancialExposure[] = [
  { asset_id: "AST-001", asset_name: "Production Web Server", business_unit: "Digital Banking", criticality: 4, ale: 26500000, asset_value: 20000000, likelihood_score: 0.81, impact_score: 0.92 },
  { asset_id: "AST-002", asset_name: "Payment Database", business_unit: "Payments", criticality: 5, ale: 27800000, asset_value: 50000000, likelihood_score: 0.78, impact_score: 0.96 },
  { asset_id: "AST-003", asset_name: "API Gateway", business_unit: "Digital Banking", criticality: 4, ale: 11200000, asset_value: 25000000, likelihood_score: 0.62, impact_score: 0.81 },
  { asset_id: "AST-004", asset_name: "Development Server", business_unit: "Engineering", criticality: 2, ale: 4940000, asset_value: 5000000, likelihood_score: 0.31, impact_score: 0.46 },
  { asset_id: "AST-005", asset_name: "Staging Database", business_unit: "Quality Assurance", criticality: 3, ale: 6800000, asset_value: 10000000, likelihood_score: 0.55, impact_score: 0.72 },
  { asset_id: "AST-006", asset_name: "Mobile Banking Service", business_unit: "Digital Banking", criticality: 5, ale: 18400000, asset_value: 32000000, likelihood_score: 0.74, impact_score: 0.89 },
  { asset_id: "AST-007", asset_name: "Treasury Workstation", business_unit: "Treasury", criticality: 5, ale: 12600000, asset_value: 15000000, likelihood_score: 0.68, impact_score: 0.77 },
  { asset_id: "AST-008", asset_name: "Customer Analytics", business_unit: "Data & Analytics", criticality: 3, ale: 7350000, asset_value: 12000000, likelihood_score: 0.42, impact_score: 0.63 },
  { asset_id: "AST-009", asset_name: "Branch Services Portal", business_unit: "Retail Banking", criticality: 4, ale: 9100000, asset_value: 18000000, likelihood_score: 0.51, impact_score: 0.7 },
  { asset_id: "AST-010", asset_name: "Backup Archive", business_unit: "Infrastructure", criticality: 3, ale: 4200000, asset_value: 9000000, likelihood_score: 0.29, impact_score: 0.58 },
];

// Recommendations reuse the existing risk-analysis demo records so investment/ROI views stay consistent.
export const executiveRecommendations: MitigationRecommendation[] = [
  { recommendation_id: "REC-001", asset_id: "AST-001", control_name: "patch deployment", investment_cost: 450000, risk_reduction: 32, roi: 3.4, priority: 1 },
  { recommendation_id: "REC-002", asset_id: "AST-001", control_name: "access control tightening", investment_cost: 280000, risk_reduction: 24, roi: 3.1, priority: 2 },
  { recommendation_id: "REC-003", asset_id: "AST-002", control_name: "network segmentation", investment_cost: 650000, risk_reduction: 21, roi: 2.2, priority: 3 },
  { recommendation_id: "REC-004", asset_id: "AST-003", control_name: "additional monitoring", investment_cost: 175000, risk_reduction: 12, roi: 2.9, priority: 4 },
  { recommendation_id: "REC-005", asset_id: "AST-004", control_name: "patch deployment", investment_cost: 120000, risk_reduction: 9, roi: 2.6, priority: 5 },
  { recommendation_id: "REC-006", asset_id: "AST-005", control_name: "access control tightening", investment_cost: 210000, risk_reduction: 8, roi: 1.9, priority: 5 },
];
