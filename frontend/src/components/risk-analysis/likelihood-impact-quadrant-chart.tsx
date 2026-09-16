"use client";

import { CartesianGrid, ReferenceLine, Scatter, ScatterChart, XAxis, YAxis } from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import type { RiskQuantificationSummary } from "@/types";

const config: ChartConfig = { asset: { label: "Asset position", color: "var(--danger)" } };
const quadrant = (likelihood: number, impact: number) => likelihood >= 0.5 ? impact >= 0.5 ? "Immediate Action" : "Contain" : impact >= 0.5 ? "Mitigate" : "Monitor";
const quadrantColor = (name: string) => name === "Immediate Action" ? "var(--danger)" : name === "Contain" ? "var(--warning)" : name === "Mitigate" ? "#92751b" : "var(--success)";

export function LikelihoodImpactQuadrantChart({ summary }: { summary: RiskQuantificationSummary }) {
  if (summary.likelihood_score == null || summary.impact_score == null) return <Card><CardHeader><CardTitle>Risk Position</CardTitle><CardDescription>Where this asset sits on the likelihood-impact matrix.</CardDescription></CardHeader><CardContent><div className="risk-pending-state">Pending risk calculation</div></CardContent></Card>;
  const point = [{ x: summary.likelihood_score, y: summary.impact_score, label: quadrant(summary.likelihood_score, summary.impact_score) }];
  return <Card><CardHeader><CardTitle>Risk Position</CardTitle><CardDescription>Where this asset sits on the likelihood-impact matrix.</CardDescription></CardHeader><CardContent><ChartContainer config={config} className="aspect-auto h-[260px] w-full"><ScatterChart accessibilityLayer data={point} margin={{ top: 28, right: 28, bottom: 42, left: 48 }}><CartesianGrid /><XAxis type="number" dataKey="x" domain={[0, 1]} tickLine={false} label={{ value: "Likelihood", position: "insideBottom", offset: -22, fill: "var(--muted-foreground)", fontSize: 12 }} /><YAxis type="number" dataKey="y" domain={[0, 1]} tickLine={false} label={{ value: "Impact", angle: -90, position: "insideLeft", offset: 6, fill: "var(--muted-foreground)", fontSize: 12 }} /><ReferenceLine x={0.5} stroke="var(--muted)" strokeDasharray="4 4" /><ReferenceLine y={0.5} stroke="var(--muted)" strokeDasharray="4 4" /><Scatter name="Asset position" data={point} fill={quadrantColor(point[0].label)} shape={({ cx, cy }) => <circle cx={cx} cy={cy} r={8} fill={quadrantColor(point[0].label)} />} /><ChartTooltip content={<ChartTooltipContent formatter={(value, name) => [Number(value).toFixed(2), name === "x" ? "Likelihood" : "Impact"]} />} /></ScatterChart></ChartContainer><div className="risk-quadrant-labels"><span>Monitor</span><span>Contain</span><span>Mitigate</span><span>Immediate Action</span></div></CardContent></Card>;
}
