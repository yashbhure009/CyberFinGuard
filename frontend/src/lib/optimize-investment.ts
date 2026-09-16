import type { MitigationRecommendation } from "@/types";

export interface InvestmentOptimizationResult {
  selected: MitigationRecommendation[];
  totalCost: number;
  totalRiskReduction: number;
  remainingBudget: number;
}

// Exact 0/1 knapsack via memoized dynamic programming. Each recommendation can be selected once.
export function optimizeInvestment(recommendations: MitigationRecommendation[], budget: number): InvestmentOptimizationResult {
  const safeBudget = Math.max(0, Math.floor(budget));
  const memo = new Map<string, { value: number; cost: number; indices: number[] }>();

  function solve(index: number, remaining: number): { value: number; cost: number; indices: number[] } {
    if (index >= recommendations.length || remaining <= 0) return { value: 0, cost: 0, indices: [] };
    const key = `${index}:${remaining}`;
    const cached = memo.get(key);
    if (cached) return cached;
    const recommendation = recommendations[index];
    const without = solve(index + 1, remaining);
    let best = without;
    if (recommendation.investment_cost <= remaining) {
      const withCurrent = solve(index + 1, remaining - recommendation.investment_cost);
      const candidate = { value: withCurrent.value + recommendation.risk_reduction, cost: withCurrent.cost + recommendation.investment_cost, indices: [index, ...withCurrent.indices] };
      if (candidate.value > best.value || (candidate.value === best.value && candidate.cost < best.cost)) best = candidate;
    }
    memo.set(key, best);
    return best;
  }

  const solution = solve(0, safeBudget);
  const selected = solution.indices.map((index) => recommendations[index]);
  return { selected, totalCost: solution.cost, totalRiskReduction: solution.value, remainingBudget: safeBudget - solution.cost };
}
