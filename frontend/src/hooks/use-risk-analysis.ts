"use client";

import { useEffect, useState } from "react";
import type { AIRecommendation, MitigationRecommendation, RiskQuantificationSummary, TechnicalFindingRow } from "@/types";
import { estimateValueAtRisk, mitigationRecommendations, riskSummary } from "@/lib/mock/risk-analysis";
import { technicalFindings } from "@/lib/mock/technical-dashboard";
import { getMitigationRecommendations } from "@/lib/api";

export function useRiskAnalysisData(assetIds?: string[]): { summary: RiskQuantificationSummary; recommendations: (MitigationRecommendation | AIRecommendation)[]; recommendationsSource: "ai" | "mock"; findings: TechnicalFindingRow[]; isLoading: boolean; error: string | null } {
  const [isLoading, setIsLoading] = useState(true);
  const [recommendations, setRecommendations] = useState<(MitigationRecommendation | AIRecommendation)[]>(mitigationRecommendations);
  const [recommendationsSource, setRecommendationsSource] = useState<"ai" | "mock">("mock");
  useEffect(() => {
    let active = true;
    async function loadRecommendations() {
      if (assetIds?.[0]) {
        try {
          const result = await getMitigationRecommendations(assetIds[0]);
          if (active) { setRecommendations(result.recommendations); setRecommendationsSource("ai"); }
        } catch { if (active) { setRecommendations([...mitigationRecommendations]); setRecommendationsSource("mock"); } }
      }
      if (active) setIsLoading(false);
    }
    void loadRecommendations();
    return () => { active = false; };
  }, [assetIds?.[0]]);
  const findings = assetIds?.length ? technicalFindings.filter((finding) => assetIds.includes(finding.asset_id)) : technicalFindings;
  return { summary: { ...riskSummary, estimatedValueAtRisk: estimateValueAtRisk(riskSummary.ale) }, recommendations: [...recommendations].sort((a, b) => a.priority - b.priority), recommendationsSource, findings, isLoading, error: null };
}
