"use client";

import { useEffect, useState } from "react";
import { getComplianceSummary } from "@/lib/api";
import { assetFinancialExposures, executiveRecommendations } from "@/lib/mock/executive-dashboard";
import type { AssetFinancialExposure, ComplianceSummary, ExecutiveDashboardSummary, MitigationRecommendation } from "@/types";

export function useExecutiveDashboardData(): {
  summary: ExecutiveDashboardSummary;
  assetExposures: AssetFinancialExposure[];
  recommendations: MitigationRecommendation[];
  complianceSummary: ComplianceSummary | null;
  isLoading: boolean;
  error: string | null;
} {
  const [complianceSummary, setComplianceSummary] = useState<ComplianceSummary | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    getComplianceSummary()
      .then((result) => { if (active) setComplianceSummary(result); })
      .catch((requestError) => { if (active) setError(requestError instanceof Error ? requestError.message : "Unable to load compliance coverage."); })
      .finally(() => { if (active) setIsLoading(false); });
    return () => { active = false; };
  }, []);

  const totalAle = assetFinancialExposures.reduce((sum, asset) => sum + asset.ale, 0);
  const totalValueAtRisk = Math.round(totalAle * 1.8);
  const totalInvestment = executiveRecommendations.reduce((sum, recommendation) => sum + recommendation.investment_cost, 0);
  const averageRoi = executiveRecommendations.length ? executiveRecommendations.reduce((sum, recommendation) => sum + recommendation.roi, 0) / executiveRecommendations.length : 0;
  const totalAssetValue = assetFinancialExposures.reduce((sum, asset) => sum + asset.asset_value, 0);
  const averageLikelihood = assetFinancialExposures.length ? assetFinancialExposures.reduce((sum, asset) => sum + asset.likelihood_score, 0) / assetFinancialExposures.length * 100 : 0;
  const averageImpact = assetFinancialExposures.length ? assetFinancialExposures.reduce((sum, asset) => sum + asset.impact_score, 0) / assetFinancialExposures.length * 100 : 0;
  // Illustrative composite weights: normalized ALE 40%, likelihood 20%, impact 20%, compliance coverage 20%.
  // ALE is normalized as enterprise ALE divided by total asset value, capped at 100.
  const normalizedAle = totalAssetValue ? Math.min(100, totalAle / totalAssetValue * 100) : 0;
  const enterpriseRiskScore = complianceSummary ? Math.round(normalizedAle * 0.4 + averageLikelihood * 0.2 + averageImpact * 0.2 + (summaryCoverage(complianceSummary) || 0) * 0.2) : null;
  const summary: ExecutiveDashboardSummary = {
    total_ale: totalAle,
    total_estimated_var: totalValueAtRisk,
    total_recommended_investment: totalInvestment,
    average_roi: averageRoi,
    critical_assets: assetFinancialExposures.filter((asset) => asset.criticality >= 5).length,
    compliance_coverage_percent: complianceSummary?.frameworks.length ? complianceSummary.frameworks.reduce((sum, framework) => sum + framework.coverage_percent, 0) / complianceSummary.frameworks.length : null,
    enterprise_risk_score: enterpriseRiskScore,
  };

  return { summary, assetExposures: assetFinancialExposures, recommendations: executiveRecommendations, complianceSummary, isLoading, error };
}

function summaryCoverage(summary: ComplianceSummary): number {
  return summary.frameworks.length ? summary.frameworks.reduce((sum, framework) => sum + framework.coverage_percent, 0) / summary.frameworks.length : 0;
}
