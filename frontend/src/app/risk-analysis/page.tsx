"use client";

import { useEffect, useState } from "react";
import { AppShell } from "@/components/layout/app-shell";
import { MitigationRecommendationsPanel } from "@/components/risk-analysis/mitigation-recommendations-panel";
import { RiskQuantificationPanel } from "@/components/risk-analysis/risk-quantification-panel";
import { useRiskAnalysisData } from "@/hooks/use-risk-analysis";
import { mockUser } from "@/lib/mock-data";

export default function RiskAnalysisPage() {
  const [assetIds, setAssetIds] = useState<string[] | undefined>();
  useEffect(() => { const value = new URLSearchParams(window.location.search).get("assetIds"); setAssetIds(value?.split(",").filter(Boolean)); }, []);
  const { summary, recommendations, recommendationsSource, findings, isLoading, error } = useRiskAnalysisData(assetIds);
  return <AppShell user={mockUser} title="Risk Quantification Workspace" eyebrow="Financial cyber risk analysis"><section className="risk-analysis-page"><div className="risk-analysis-intro"><p className="dashboard-kicker">Quantify <span>→</span> Prioritize <span>→</span> Act</p><p className="dashboard-description">Translate current technical exposure into financial context and practical mitigation priorities.</p></div>{error && <p className="error-text">{error}</p>}{isLoading ? <div className="risk-loading app-card">Loading risk analysis…</div> : <div className="risk-analysis-grid"><RiskQuantificationPanel summary={summary} findings={findings} /><MitigationRecommendationsPanel recommendations={recommendations} source={recommendationsSource} /></div>}</section></AppShell>;
}
