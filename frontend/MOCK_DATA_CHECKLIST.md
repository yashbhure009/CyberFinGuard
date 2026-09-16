# Technical dashboard mock-data checklist

Replace these mock or placeholder sources when the real integrations are ready:

- `src/lib/mock/technical-dashboard.ts` — `technicalFindingSeeds`, `joinedAssetData`, and `technicalSummary` are static findings, asset joins, and KPI calculations. Replace with normalized findings and joined asset/risk data from `GET /api/dashboard/technical`, populated by the findings, assets, controls, and `risk_scores` tables.
- `src/hooks/use-technical-dashboard.ts` — `useTechnicalDashboardData()` returns imported mock findings after a client-side loading timer. Replace with a real request to `GET /api/dashboard/technical` and its loading/error handling.
- `src/components/technical/technical-dashboard-live.tsx` — loading text and chart-slot fallback copy are UI placeholders; replace them with the API's loading/empty states once all dashboard panels are backed by data.
- `src/lib/technical-dashboard/aggregate-by-severity.ts` — severity distribution is calculated from the mock findings until the backend supplies an aggregated distribution.
- `src/lib/technical-dashboard/aggregate-trend.ts` — the 30-day trend is calculated from mock finding timestamps; replace with backend time-series data when available.
- `src/lib/technical-dashboard/group-by-severity-scatter.ts` — CVSS/EPSS points are grouped from mock findings; use normalized backend scores when available.
- `src/lib/technical-dashboard/aggregate-emerging-risk.ts` — emerging risk is a transparent rules-based composite and simple projection over mock findings; replace with a backend risk-signal series once the risk engine and `risk_scores` table provide it.
- `src/components/technical/charts/emerging-risk-trend-chart.tsx` — renders the aggregation above and therefore remains mock-backed until that helper receives real risk-signal data.
- `src/components/technical/technical-dashboard-live.tsx` — KPI values come from `technicalSummary` through the mock hook; replace with backend summary fields when the endpoint is implemented.
- `src/lib/mock/risk-analysis.ts` — `riskSummary` and `mitigationRecommendations` stand in for `risk_scores` and `investment_recommendations`; replace with records from the risk engine/API once populated.
- `src/hooks/use-risk-analysis.ts` — `useRiskAnalysisData()` returns mock risk and recommendation records after a client-side loading timer; replace with the risk-analysis API call.
- `src/lib/mock/risk-analysis.ts` — `estimateValueAtRisk()` uses `ALE × 1.8` as an illustrative percentile-style tail-loss estimate; replace it with a backend-computed VaR if one is added.
- `src/components/risk-analysis/risk-quantification-panel.tsx` and `src/components/risk-analysis/mitigation-recommendations-panel.tsx` — render the mock-backed workspace; keep the panels and swap their hook data to real risk-engine results.
