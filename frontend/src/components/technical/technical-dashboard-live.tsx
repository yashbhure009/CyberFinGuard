"use client";

import { useEffect, useMemo, useState } from "react";
import { useTechnicalDashboardData } from "@/hooks/use-technical-dashboard";
import type { TechnicalFindingRow } from "@/types";
import { VulnerabilityTrendChart } from "@/components/technical/charts/vulnerability-trend-chart";
import { FindingsBySeverityChart } from "@/components/technical/charts/findings-by-severity-chart";
import { CvssEpssScatterChart } from "@/components/technical/charts/cvss-epss-scatter-chart";
import { EmergingRiskTrendChart } from "@/components/technical/charts/emerging-risk-trend-chart";
import { weightedRiskScore } from "@/lib/technical-dashboard/weighted-risk";

function AnimatedKpiValue({
  value,
  loading,
}: {
  value: number | string;
  loading: boolean;
}) {
  const target = typeof value === "number" ? value : Number.parseInt(value, 10);
  const suffix = typeof value === "string" && value.endsWith("%") ? "%" : "";
  const [display, setDisplay] = useState(0);

  useEffect(() => {
    if (loading) return;
    setDisplay(0);
    const duration = 900;
    const started = performance.now();
    let frame = 0;
    const tick = (now: number) => {
      const progress = Math.min((now - started) / duration, 1);
      setDisplay(Math.round(target * (1 - Math.pow(1 - progress, 3))));
      if (progress < 1) frame = requestAnimationFrame(tick);
    };
    frame = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(frame);
  }, [loading, target]);

  return <>{loading ? "—" : `${display}${suffix}`}</>;
}

const chartSlots = [
  ["Findings by severity", "Severity distribution will be connected next."],
  ["CVSS vs EPSS", "Technical severity versus exploitation likelihood."],
  ["Vulnerability trend", "Findings over time will be connected next."],
];

export function TechnicalDashboardLive() {
  const { summary, findings, isLoading, error } = useTechnicalDashboardData();
  const [severity, setSeverity] = useState("all");
  const [source, setSource] = useState("all");
  const [patch, setPatch] = useState("all");
  const [assetId, setAssetId] = useState("all");
  const [sortBy, setSortBy] = useState<"default" | "weightedRisk">("default");
  const [selected, setSelected] = useState<TechnicalFindingRow | null>(null);
  useEffect(() => {
    const requestedAssetId = new URLSearchParams(window.location.search).get("assetId");
    if (requestedAssetId) setAssetId(requestedAssetId);
  }, []);
  const filtered = useMemo(
    () =>
      findings.filter(
        (finding) =>
          (severity === "all" || finding.severity === severity) &&
          (source === "all" || finding.source === source) &&
          (patch === "all" || finding.patching_status === patch) &&
          (assetId === "all" || finding.asset_id === assetId),
      ),
    [findings, severity, source, patch, assetId],
  );
  const displayedFindings = useMemo(() => sortBy === "default" ? filtered : [...filtered].sort((a, b) => weightedRiskScore(b) - weightedRiskScore(a)), [filtered, sortBy]);
  const kpis = [
    ["Total findings", summary.total_findings],
    ["Critical", summary.critical_findings],
    ["Unpatched", summary.unpatched_findings],
    ["Exploitable", summary.exploitable_findings],
    ["Patch compliance", `${summary.patch_compliance_percent}%`],
    ["MFA / EDR coverage", `${summary.mfa_edr_coverage_percent}%`],
  ];

  return (
    <section
      className="technical-dashboard"
      aria-label="Technical security dashboard"
    >
      <div className="dashboard-intro">
        <div>
          <p className="dashboard-kicker">
            Observe <span>→</span> Investigate <span>→</span> Remediate
          </p>
          <p className="dashboard-description">
            A live operational view of vulnerabilities, controls, threat
            intelligence and remediation evidence.
          </p>
        </div>
        <span className="data-status">
          <span className="data-status-dot" /> Mock schema-aligned data
        </span>
      </div>
      <div className="technical-kpi-grid">
        {kpis.map(([label, value]) => (
          <article
            className={`app-card technical-kpi-card ${label === "Critical" ? "critical-kpi-card" : ""}`}
            key={label as string}
          >
            <p>{label}</p>
            <strong>
              <AnimatedKpiValue value={value} loading={isLoading} />
            </strong>
          </article>
        ))}
      </div>
      <div className="technical-view-grid technical-chart-grid">
        {chartSlots.map(([title, description]) =>
          title === "Findings by severity" ? (
            isLoading ? (
              <article className="app-card technical-placeholder" key={title}>
                <div className="placeholder-body">
                  Loading severity distribution…
                </div>
              </article>
            ) : (
              <FindingsBySeverityChart findings={findings} key={title} />
            )
          ) : title === "Vulnerability trend" ? (
            isLoading ? (
              <article className="app-card technical-placeholder" key={title}>
                <div className="placeholder-body">Loading trend…</div>
              </article>
            ) : (
              <VulnerabilityTrendChart findings={findings} key={title} />
            )
          ) : title === "CVSS vs EPSS" ? (
            isLoading ? (
              <article className="app-card technical-placeholder" key={title}>
                <div className="placeholder-body">Loading CVSS / EPSS…</div>
              </article>
            ) : (
              <CvssEpssScatterChart findings={findings} key={title} />
            )
          ) : (
            <article className="app-card technical-placeholder" key={title}>
              <div className="placeholder-heading">
                <div>
                  <h2>{title}</h2>
                  <p>{description}</p>
                </div>
                <span className="placeholder-badge">Chart slot</span>
              </div>
              <div className="placeholder-body">
                Chart implementation pending.
              </div>
            </article>
          ),
        )}
      </div>
      {!isLoading && <div className="emerging-risk-row"><EmergingRiskTrendChart findings={findings} /></div>}
      <div className="technical-filter-bar app-card">
        <label>
          Severity
          <select
            value={severity}
            onChange={(event) => setSeverity(event.target.value)}
          >
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
        </label>
        <label>
          Source
          <select
            value={source}
            onChange={(event) => setSource(event.target.value)}
          >
            <option value="all">All</option>
            {Array.from(new Set(findings.map((finding) => finding.source))).map(
              (value) => (
                <option key={value}>{value}</option>
              ),
            )}
          </select>
        </label>
        <label>
          Patch
          <select
            value={patch}
            onChange={(event) => setPatch(event.target.value)}
          >
            <option value="all">All</option>
            <option value="patched">Patched</option>
            <option value="partial">Partial</option>
            <option value="unpatched">Unpatched</option>
          </select>
        </label>
        <label>
          Sort
          <select value={sortBy} onChange={(event) => setSortBy(event.target.value as typeof sortBy)}><option value="default">Default</option><option value="weightedRisk">Weighted risk</option></select>
        </label>
        <span className="filter-count">{filtered.length} findings</span>
      </div>
      {error && <p className="error-text">{error}</p>}
      <div className="technical-findings-wrap app-card">
        <div className="technical-section-heading">
          <div>
            <p className="eyebrow">Normalized findings</p>
            <h2>Findings register</h2>
          </div>
          <span className="table-note">Select a row for details</span>
        </div>
        {isLoading ? (
          <div className="technical-empty">Loading findings…</div>
        ) : filtered.length === 0 ? (
          <div className="technical-empty">
            No findings match the active filters.
          </div>
        ) : (
          <div className="technical-table-scroll">
            <table className="technical-table">
              <thead>
                <tr>
                  {[
                    "ID",
                    "Asset",
                    "CVE",
                    "CVSS",
                    "EPSS",
                    "Patch",
                    "Severity",
                    "Likelihood",
                    "Weighted Risk",
                  ].map((heading) => (
                    <th key={heading}>{heading}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {displayedFindings.map((finding) => (
                  <tr
                    key={finding.finding_id}
                    onClick={() => setSelected(finding)}
                    tabIndex={0}
                    onKeyDown={(event) =>
                      event.key === "Enter" && setSelected(finding)
                    }
                  >
                    <td>{finding.finding_id}</td>
                    <td>{finding.asset_name}</td>
                    <td>{finding.cve_id || "—"}</td>
                    <td>{finding.cvss_score ?? "—"}</td>
                    <td>{finding.epss_score?.toFixed(2) ?? "—"}</td>
                    <td>{finding.patching_status}</td>
                    <td>
                      <span className={`severity severity-${finding.severity}`}>
                        {finding.severity}
                      </span>
                    </td>
                    <td>{finding.likelihood_score?.toFixed(2) ?? "Pending"}</td>
                    <td>{weightedRiskScore(finding).toFixed(2)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {selected && (
        <aside className="technical-drawer" aria-label="Finding details">
          <button className="drawer-close" onClick={() => setSelected(null)}>
            Close
          </button>
          <p className="eyebrow">Finding detail</p>
          <h2>{selected.title}</h2>
          <p className="drawer-subtitle">
            {selected.finding_id} · {selected.asset_name}
          </p>
          <dl>
            <dt>CVE / CVSS / EPSS</dt>
            <dd>
              {selected.cve_id || "—"} · {selected.cvss_score ?? "—"} ·{" "}
              {selected.epss_score?.toFixed(2) ?? "—"}
            </dd>
            <dt>CISA KEV / Exploit</dt>
            <dd>
              {selected.cisa_kev ? "Yes" : "No"} ·{" "}
              {selected.exploit_available
                ? selected.exploit_type || "Available"
                : "No known exploit"}
            </dd>
            <dt>MITRE technique</dt>
            <dd>{selected.mitre_technique || "—"}</dd>
            <dt>Controls</dt>
            <dd>
              MFA {selected.mfa_enabled ? "enabled" : "disabled"} · WAF{" "}
              {selected.waf_enabled ? "enabled" : "disabled"} · EDR{" "}
              {selected.edr_enabled ? "enabled" : "disabled"} · Patch{" "}
              {selected.patching_status}
            </dd>
            <dt>Risk calculation</dt>
            <dd>
              {selected.likelihood_score === undefined ||
              selected.impact_score === undefined ||
              selected.ale === undefined
                ? "Pending risk calculation"
                : `Likelihood ${selected.likelihood_score.toFixed(2)} · Impact ${selected.impact_score.toFixed(2)} · ALE ₹${selected.ale.toLocaleString("en-IN")}`}
            </dd>
          </dl>
        </aside>
      )}
    </section>
  );
}
