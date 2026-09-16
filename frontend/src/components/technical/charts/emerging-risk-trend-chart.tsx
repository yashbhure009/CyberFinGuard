"use client";

import { useMemo } from "react";
import { Area, AreaChart, CartesianGrid, ReferenceLine, XAxis, YAxis } from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import type { TechnicalFindingRow } from "@/types";
import { aggregateEmergingRisk } from "@/lib/technical-dashboard/aggregate-emerging-risk";

const config: ChartConfig = { score: { label: "Composite risk signal", color: "var(--danger)" }, projectedScore: { label: "Projected signal", color: "var(--warning)" } };

export function EmergingRiskTrendChart({ findings }: { findings: TechnicalFindingRow[] }) {
  const data = useMemo(() => aggregateEmergingRisk(findings).map((point) => ({ ...point, projectedScore: point.projected ? point.score : undefined })), [findings]);
  const today = data.find((point) => point.projected)?.date;
  return <Card className="emerging-risk-chart-card"><CardHeader><CardTitle>Emerging Risk Trend</CardTitle><CardDescription>Composite risk signal from finding volume, severity, and exploit activity — projected trend is a simple statistical extrapolation, not a predictive model.</CardDescription></CardHeader><CardContent><ChartContainer config={config} className="aspect-auto h-[250px] w-full"><AreaChart accessibilityLayer data={data} margin={{ left: 8, right: 12, top: 8, bottom: 8 }}><CartesianGrid vertical={false} /><XAxis dataKey="date" tickFormatter={(value) => value.slice(5)} /><YAxis allowDecimals={false} /><ChartTooltip content={<ChartTooltipContent formatter={(value, name, item) => { const point = item.payload; if (name === "score" || name === "projectedScore") return [Number(value).toFixed(0), `${name === "score" ? "Composite risk signal" : "Projected signal"} · ${point.findingCount} findings · severity ${point.severityContribution} · exploit ${point.exploitContribution}`]; return [value, name]; }} />} />{today && <ReferenceLine x={today} stroke="var(--muted)" strokeDasharray="4 4" label={{ value: "Today", position: "insideTopRight", fill: "var(--muted-foreground)", fontSize: 11 }} />}<Area type="monotone" dataKey="score" stroke="var(--color-score)" fill="var(--color-score)" fillOpacity={0.18} connectNulls={false} /><Area type="monotone" dataKey="projectedScore" stroke="var(--color-projectedScore)" strokeDasharray="6 4" fill="var(--color-projectedScore)" fillOpacity={0.08} connectNulls={false} /></AreaChart></ChartContainer></CardContent></Card>;
}
