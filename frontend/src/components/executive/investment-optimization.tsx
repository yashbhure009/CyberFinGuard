"use client";

import { useMemo, useState, type FormEvent } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { optimizeInvestment } from "@/lib/optimize-investment";
import type { ExecutiveDashboardSummary, MitigationRecommendation } from "@/types";

const money = (value: number) => `₹${Math.round(value).toLocaleString("en-IN")}`;
const percent = (value: number) => `${value.toFixed(1)}%`;

function RemediationBacklog({ recommendations, selected }: { recommendations: MitigationRecommendation[]; selected: MitigationRecommendation[] }) {
  const selectedIds = new Set(selected.map((recommendation) => recommendation.recommendation_id));
  const openItems = recommendations.filter((recommendation) => !selectedIds.has(recommendation.recommendation_id));
  return <Card className="remediation-backlog-card"><CardHeader><CardTitle>Remediation Backlog</CardTitle><CardDescription>Open recommendations not included in the current optimized allocation.</CardDescription></CardHeader><CardContent>{openItems.length ? <div className="optimization-table-wrap"><table className="optimization-table"><thead><tr><th>Control</th><th>Priority</th><th>Cost</th><th>Status</th></tr></thead><tbody>{openItems.map((recommendation) => <tr key={recommendation.recommendation_id}><td>{recommendation.control_name}</td><td>Priority {recommendation.priority}</td><td>{money(recommendation.investment_cost)}</td><td>Open</td></tr>)}</tbody></table></div> : <p className="optimization-empty">No open recommendations remain outside the optimized allocation.</p>}</CardContent></Card>;
}

export function InvestmentOptimization({ recommendations, summary }: { recommendations: MitigationRecommendation[]; summary: ExecutiveDashboardSummary }) {
  const [budgetText, setBudgetText] = useState("");
  const [budget, setBudget] = useState<number | null>(null);
  const result = useMemo(() => budget == null ? null : optimizeInvestment(recommendations, budget), [budget, recommendations]);
  const reductionValue = (riskReduction: number) => summary.total_ale * (riskReduction / 100);
  const rosi = (recommendation: MitigationRecommendation) => (reductionValue(recommendation.risk_reduction) - recommendation.investment_cost) / recommendation.investment_cost;
  const payback = (recommendation: MitigationRecommendation) => { const value = reductionValue(recommendation.risk_reduction); return value > 0 ? `~${Math.max(1, Math.round((recommendation.investment_cost / value) * 12))} months of ALE reduction` : "Not available"; };

  function applyBudget(event: FormEvent) {
    event.preventDefault();
    const parsed = Number(budgetText.replace(/,/g, ""));
    setBudget(Number.isFinite(parsed) && parsed >= 0 ? Math.floor(parsed) : 0);
  }

  return <><Card className="investment-optimization-card"><CardHeader><CardTitle>Investment Optimization</CardTitle><CardDescription>Exact budget allocation across current recommendations — deterministic 0/1 knapsack optimization, not AI.</CardDescription></CardHeader><CardContent><form className="optimization-budget-form" onSubmit={applyBudget}><label htmlFor="security-budget">Enter security budget (₹)</label><div><input id="security-budget" inputMode="numeric" type="number" min="0" step="1" value={budgetText} onChange={(event) => setBudgetText(event.target.value)} placeholder="₹1,00,00,000" /><button type="submit">Apply budget</button></div></form>{result == null ? <p className="optimization-empty">Enter a budget to see the optimal set of controls.</p> : result.selected.length === 0 ? <p className="optimization-empty">No recommendation fits within this budget. Increase the budget to evaluate an allocation.</p> : <div className="optimization-output"><div className="optimization-summary"><div><span>Selected cost</span><strong>{money(result.totalCost)}</strong></div><div><span>Unused budget</span><strong>{money(result.remainingBudget)}</strong></div><div><span>Risk reduction</span><strong>{percent(result.totalRiskReduction)}</strong></div></div><p className="optimization-note">Optimization based on current recommendation data — not a real-time market analysis.</p><div className="optimization-table-wrap"><table className="optimization-table"><thead><tr><th>Control</th><th>Cost</th><th>Risk reduction value</th><th>ROSI</th><th>Payback framing</th></tr></thead><tbody>{result.selected.map((recommendation) => <tr key={recommendation.recommendation_id}><td>{recommendation.control_name}</td><td>{money(recommendation.investment_cost)}</td><td>{money(reductionValue(recommendation.risk_reduction))}</td><td>{percent(rosi(recommendation) * 100)}</td><td>{payback(recommendation)}</td></tr>)}</tbody></table></div></div>}</CardContent></Card>{result != null && <RemediationBacklog recommendations={recommendations} selected={result.selected} />}</>;
}
