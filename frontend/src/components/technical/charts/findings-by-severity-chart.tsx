"use client";

import { useMemo } from "react";
import { Pie, PieChart } from "recharts";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import type { TechnicalFindingRow } from "@/types";
import { aggregateFindingsBySeverity } from "@/lib/technical-dashboard/aggregate-by-severity";
import { technicalSeverityConfig } from "@/lib/technical-dashboard/severity-config";

export function FindingsBySeverityChart({ findings }: { findings: TechnicalFindingRow[] }) {
  const { data, total } = useMemo(() => aggregateFindingsBySeverity(findings), [findings]);
  const criticalHigh = data.filter((item) => item.severity === "critical" || item.severity === "high").reduce((sum, item) => sum + item.count, 0);
  const highShare = total ? Math.round((criticalHigh / total) * 100) : 0;
  const chartConfig = Object.fromEntries(data.map((item) => [item.severity, technicalSeverityConfig[item.severity as keyof typeof technicalSeverityConfig]])) as ChartConfig;
  return <Card className="severity-chart-card"><CardHeader><CardTitle>Findings by Severity</CardTitle><CardDescription>Current distribution across all findings</CardDescription></CardHeader><CardContent><ChartContainer config={chartConfig} className="mx-auto aspect-square max-h-[220px]"><PieChart><ChartTooltip content={<ChartTooltipContent hideLabel />} /><Pie data={data} dataKey="count" nameKey="severity" innerRadius={60} label={({ percent }) => `${Math.round((percent || 0) * 100)}%`} labelLine isAnimationActive animationBegin={0} animationDuration={800} animationEasing="ease-out" /></PieChart></ChartContainer></CardContent><CardFooter>{total} total findings — {highShare}% Critical or High</CardFooter></Card>;
}
