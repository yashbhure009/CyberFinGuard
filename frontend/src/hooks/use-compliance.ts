"use client";

import { useEffect, useState } from "react";
import { getComplianceFindings, getComplianceSummary } from "@/lib/api";
import type { ComplianceFindingMapping, ComplianceSummary } from "@/types";

export function useComplianceData(): { summary: ComplianceSummary | null; findings: ComplianceFindingMapping[]; isLoading: boolean; error: string | null } {
  const [summary, setSummary] = useState<ComplianceSummary | null>(null);
  const [findings, setFindings] = useState<ComplianceFindingMapping[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    Promise.all([getComplianceSummary(), getComplianceFindings()])
      .then(([summaryResult, findingsResult]) => {
        if (!active) return;
        setSummary(summaryResult);
        setFindings(findingsResult.findings);
      })
      .catch((requestError) => {
        if (active) setError(requestError instanceof Error ? requestError.message : "Unable to load compliance data.");
      })
      .finally(() => { if (active) setIsLoading(false); });
    return () => { active = false; };
  }, []);

  return { summary, findings, isLoading, error };
}
