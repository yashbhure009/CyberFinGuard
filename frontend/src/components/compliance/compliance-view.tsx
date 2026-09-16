"use client";

import { FileCheck2, ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { useComplianceData } from "@/hooks/use-compliance";
import type { ComplianceFindingMapping } from "@/types";

const severityClass = (severity: ComplianceFindingMapping["severity"]) => severity === "critical" ? "severity-critical" : severity === "high" ? "severity-high" : severity === "medium" ? "severity-medium" : severity === "low" ? "severity-low" : "severity-medium";

export function ComplianceView() {
  const { summary, findings, isLoading, error } = useComplianceData();

  if (isLoading) return <div className="compliance-page"><div className="compliance-loading app-card">Loading compliance coverage…</div></div>;
  if (error || !summary) return <div className="compliance-page"><div className="compliance-error app-card"><ShieldAlert size={20} /><div><strong>Compliance data unavailable</strong><p>{error || "The compliance service did not return a summary."}</p></div></div></div>;

  return <section className="compliance-page">
    <div className="dashboard-intro"><div><p className="dashboard-kicker">Map <span>→</span> Measure <span>→</span> Improve</p><p className="dashboard-description">See how current findings align with the control references used by your organization.</p></div><div className="data-status"><span className="online-dot" /> Live query-time mapping</div></div>
    <div className="compliance-overview"><div><p className="eyebrow">Coverage overview</p><h2>Framework posture</h2></div><p className="compliance-note">Mappings are derived from current finding source/title data, with CWE fallback where available.</p></div>
    <div className="compliance-framework-grid">{summary.frameworks.map((framework) => <Card className="compliance-framework-card" key={framework.framework}><CardHeader><CardTitle>{framework.framework}</CardTitle></CardHeader><CardContent><strong>{framework.coverage_percent}%</strong><span>{framework.mapped_findings} of {summary.total_findings} findings mapped</span><div className="compliance-progress"><span style={{ width: `${framework.coverage_percent}%` }} /></div></CardContent></Card>)}</div>
    <Card className="compliance-table-card"><CardHeader><CardTitle><FileCheck2 size={17} /> Findings to framework controls</CardTitle><p className="compliance-table-meta">{summary.unmapped_findings} unmapped of {summary.total_findings} total findings</p></CardHeader><CardContent><div className="compliance-table-scroll"><table className="compliance-table"><thead><tr><th>Finding</th><th>Severity</th><th>Asset</th><th>Framework mappings</th></tr></thead><tbody>{findings.length === 0 ? <tr><td colSpan={4} className="compliance-empty">No findings available for mapping.</td></tr> : findings.map((finding) => <tr key={finding.finding_id}><td><strong>{finding.title}</strong><small>{finding.finding_id}</small></td><td><span className={`severity ${severityClass(finding.severity)}`}>{finding.severity}</span></td><td>{finding.asset_id || "—"}</td><td><div className="compliance-tags">{finding.mappings.map((mapping) => <span className={`compliance-tag ${mapping.framework === "Unmapped" ? "compliance-tag-unmapped" : ""}`} key={`${mapping.framework}-${mapping.control_id || "none"}`}><b>{mapping.framework}</b>{mapping.control_id && <small>{mapping.control_id}</small>}</span>)}</div></td></tr>)}</tbody></table></div></CardContent></Card>
  </section>;
}
