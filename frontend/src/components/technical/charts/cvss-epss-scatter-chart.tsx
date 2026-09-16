"use client";

import { useMemo } from "react";
import { CartesianGrid, ReferenceLine, Scatter, ScatterChart, XAxis, YAxis } from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ChartContainer, ChartLegend, ChartLegendContent, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import type { TechnicalFindingRow } from "@/types";
import { groupBySeverityForScatter } from "@/lib/technical-dashboard/group-by-severity-scatter";
import { technicalSeverityConfig } from "@/lib/technical-dashboard/severity-config";

const colors: Record<string, string> = Object.fromEntries(Object.entries(technicalSeverityConfig).map(([key, value]) => [key, value.color]));

export function CvssEpssScatterChart({ findings }: { findings: TechnicalFindingRow[] }) {
  const groups = useMemo(() => groupBySeverityForScatter(findings), [findings]);
  const config: ChartConfig = Object.fromEntries(groups.map((group) => [group.key, { label: technicalSeverityConfig[group.key as keyof typeof technicalSeverityConfig].label, color: colors[group.key] }])) as ChartConfig;
  return <Card className="scatter-chart-card"><CardHeader><CardTitle>CVSS vs EPSS</CardTitle><CardDescription>Severity score against real-world exploitation probability</CardDescription><p className="scatter-caption">Dashed lines mark the high-priority zone: CVSS ≥ 7 and EPSS ≥ 0.5</p></CardHeader><CardContent><ChartContainer config={config} className="aspect-auto h-[320px] w-full"><ScatterChart accessibilityLayer margin={{ top: 16, right: 24, bottom: 34, left: 42 }}><CartesianGrid /><XAxis type="number" dataKey="x" name="CVSS Score" domain={[0, 10]} label={{ value: "CVSS Score", position: "insideBottom", offset: -18, fill: "var(--muted-foreground)", fontSize: 11 }} /><YAxis type="number" dataKey="y" name="EPSS Score" domain={[0, 1]} label={{ value: "EPSS Score", angle: -90, position: "insideLeft", offset: 0, fill: "var(--muted-foreground)", fontSize: 11 }} /><ChartTooltip cursor={{ strokeDasharray: "3 3" }} content={<ChartTooltipContent formatter={(value, name) => [Number(value).toFixed(2), name === "x" ? "CVSS Score" : "EPSS Score"]} />} /><ReferenceLine x={7} stroke="var(--muted)" strokeDasharray="4 4" /><ReferenceLine y={0.5} stroke="var(--muted)" strokeDasharray="4 4" />{groups.map((group, index) => <Scatter key={group.key} name={group.key} data={group.points} fill={`var(--color-${group.key})`} isAnimationActive animationDuration={600} animationBegin={index * 150} animationEasing="ease-out" />)}<ChartLegend content={<ChartLegendContent />} /></ScatterChart></ChartContainer></CardContent></Card>;
}
