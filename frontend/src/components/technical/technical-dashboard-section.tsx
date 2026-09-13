const kpis = [
  { label: "Total findings", value: "—" },
  { label: "Critical findings", value: "—" },
  { label: "High findings", value: "—" },
  { label: "Unpatched findings", value: "—" },
  { label: "Exploitable findings", value: "—" },
  { label: "Assets monitored", value: "—" },
  { label: "Patch compliance", value: "—" },
  { label: "MFA / EDR coverage", value: "—" },
];

const plannedViews = [
  ["Findings by severity", "Operational severity distribution"],
  ["CVSS vs EPSS", "Technical severity versus exploitation likelihood"],
  ["Vulnerability trend", "Findings over time"],
  ["Control coverage", "MFA, EDR and security controls"],
  ["Top risky assets", "Assets requiring attention"],
];

export function TechnicalDashboardSection() {
  return (
    <section className="technical-dashboard" aria-label="Technical security dashboard">
      <div className="dashboard-intro">
        <div>
          <p className="dashboard-kicker">Observe <span>→</span> Investigate <span>→</span> Remediate</p>
          <p className="dashboard-description">A live operational view of vulnerabilities, controls, threat intelligence and remediation evidence.</p>
        </div>
        <span className="data-status"><span className="data-status-dot" /> Awaiting normalized data</span>
      </div>

      <div className="technical-kpi-grid">
        {kpis.map((kpi) => (
          <article className="app-card technical-kpi-card" key={kpi.label}>
            <p>{kpi.label}</p>
            <strong>{kpi.value}</strong>
          </article>
        ))}
      </div>

      <div className="technical-view-grid">
        {plannedViews.map(([title, description]) => (
          <article className="app-card technical-placeholder" key={title}>
            <div className="placeholder-heading">
              <div>
                <h2>{title}</h2>
                <p>{description}</p>
              </div>
              <span className="placeholder-badge">Planned</span>
            </div>
            <div className="placeholder-body">This visualization will be connected one component at a time.</div>
          </article>
        ))}
      </div>
    </section>
  );
}
