"use client";

import { useMemo } from "react";
import { Area, AreaChart, CartesianGrid, ReferenceArea, ReferenceLine, XAxis, YAxis } from "recharts";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ChartContainer, ChartTooltip, ChartTooltipContent, type ChartConfig } from "@/components/ui/chart";
import type { MitigationRecommendation } from "@/types";

const money = (value: number) => `₹${Math.round(value).toLocaleString("en-IN")}`;

export function InvestmentRiskReductionCurveChart({ recommendations }: { recommendations: MitigationRecommendation[] }) {
  const data = useMemo(() => {
    let investment = 0;
    let reduction = 0;
    return [...recommendations].sort((a, b) => b.roi - a.roi).map((recommendation, index) => {
      investment += recommendation.investment_cost;
      reduction += recommendation.risk_reduction;
      return { step: index + 1, investment, reduction, label: recommendation.control_name };
    });
  }, [recommendations]);
  const optimalSpendEnd = data[Math.min(3, data.length - 1)]?.investment || 0;
  const config: ChartConfig = { reduction: { label: "Cumulative risk reduction", color: "var(--accent)" } };
  return <Card className="executive-curve-card"><CardHeader><CardTitle>Investment vs. Risk Reduction — Diminishing Returns</CardTitle><CardDescription>Derived from current recommendation data; the curve is an illustrative prioritization aid, not a guaranteed outcome.</CardDescription></CardHeader><CardContent><ChartContainer config={config} className="aspect-auto h-[380px] w-full"><AreaChart data={data} margin={{ top: 28, right: 28, bottom: 48, left: 62 }}><CartesianGrid vertical={false} /><XAxis type="number" dataKey="investment" domain={[0, "auto"]} tickFormatter={(value) => money(Number(value))} label={{ value: "Cumulative investment", position: "insideBottom", offset: -28, fill: "var(--muted-foreground)", fontSize: 11 }} /><YAxis domain={[0, "auto"]} tickFormatter={(value) => `${value}%`} label={{ value: "Cumulative risk reduction %", angle: -90, position: "insideLeft", offset: 2, fill: "var(--muted-foreground)", fontSize: 11 }} /><ChartTooltip cursor={{ fill: "transparent" }} content={<ChartTooltipContent formatter={(value, name) => [name === "reduction" ? `${value}%` : money(Number(value)), name === "reduction" ? "Cumulative risk reduction" : "Cumulative investment"]} />} />{optimalSpendEnd > 0 && <><ReferenceArea x1={0} x2={optimalSpendEnd} fill="var(--accent)" fillOpacity={0.06} label={{ value: "Optimal spend zone", position: "insideTopLeft", fill: "var(--accent)", fontSize: 11 }} /><ReferenceLine x={optimalSpendEnd} stroke="var(--accent)" strokeDasharray="5 5" /></>}<Area type="monotone" dataKey="reduction" stroke="var(--color-reduction)" fill="var(--color-reduction)" fillOpacity={0.18} dot={{ r: 4, fill: "var(--accent)" }} activeDot={{ r: 6 }} /></AreaChart></ChartContainer></CardContent></Card>;
}
