"use client";

import { useEffect, useState } from "react";
import type { TechnicalDashboardSummary, TechnicalFindingRow } from "@/types";
import { technicalFindings, technicalSummary } from "@/lib/mock/technical-dashboard";

export function useTechnicalDashboardData(): { summary: TechnicalDashboardSummary; findings: TechnicalFindingRow[]; isLoading: boolean; error: string | null } {
  const [isLoading, setIsLoading] = useState(true);
  useEffect(() => {
    const timer = window.setTimeout(() => setIsLoading(false), 350);
    return () => window.clearTimeout(timer);
  }, []);
  return { summary: technicalSummary, findings: technicalFindings, isLoading, error: null };
}
