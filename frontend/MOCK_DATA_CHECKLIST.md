# Technical dashboard mock-data checklist

## Executive Dashboard

- `src/lib/mock/executive-dashboard.ts` — asset-level ALE, asset value, and recommendation records used by the Executive Dashboard; these stand in for risk_scores and investment_recommendations until the risk engine is populated.
- `src/hooks/use-executive-dashboard.ts` — combines executive mock financial records with the real `GET /api/compliance/summary` response; compliance coverage is not mock data.
- `src/components/executive/executive-dashboard.tsx` — six visualizations aggregate executive mock records; the compliance coverage chart consumes the real compliance summary.
- `src/app/dashboard/executive/page.tsx` — financial KPIs/charts are mock-backed and compliance coverage is live when PostgreSQL/API access is available.

## Compliance and AI status

- `src/hooks/use-compliance.ts` and `src/components/compliance/compliance-view.tsx` — compliance view is real DB-backed through `/api/compliance/summary` and `/api/compliance/findings`; it has no frontend compliance mock fallback.
- `src/hooks/use-risk-analysis.ts` — AI recommendation requests fall back silently to `src/lib/mock/risk-analysis.ts` when the backend/OpenRouter request fails; the UI labels the resulting source as mock.
- `src/components/chat/assistant-widget.tsx` — Ask and Simulate use the backend assistant endpoint; no frontend mock answer fallback exists.

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
