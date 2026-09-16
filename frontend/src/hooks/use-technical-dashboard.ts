"use client";

import { useCallback, useEffect, useState } from "react";
import type { TechnicalDashboardSummary, TechnicalFindingRow } from "@/types";
import { getTechnicalDashboardData } from "@/lib/api";

const initialSummary: TechnicalDashboardSummary = {
  total_findings: 0,
  critical_findings: 0,
  unpatched_findings: 0,
  exploitable_findings: 0,
  patch_compliance_percent: 0,
  mfa_edr_coverage_percent: 0,
};

export function useTechnicalDashboardData(): {
  summary: TechnicalDashboardSummary;
  findings: TechnicalFindingRow[];
  isLoading: boolean;
  error: string | null;
  refetch: () => Promise<void>;
} {
  const [summary, setSummary] = useState<TechnicalDashboardSummary>(initialSummary);
  const [findings, setFindings] = useState<TechnicalFindingRow[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchDashboardData = useCallback(async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await getTechnicalDashboardData();
      if (data && data.summary) {
        setSummary(data.summary);
        setFindings(data.findings || []);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load dashboard data");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchDashboardData();
  }, [fetchDashboardData]);

  return { summary, findings, isLoading, error, refetch: fetchDashboardData };
}
