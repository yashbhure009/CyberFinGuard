import { AppShell } from "@/components/layout/app-shell";
import { mockUser } from "@/lib/mock-data";

const kpis = [
  ["Enterprise risk score", "62 / 100"], ["Financial exposure", "₹18.4M"],
  ["Expected annual loss", "₹4.2M"], ["Value at risk", "₹7.8M"],
  ["High-risk assets", "12"], ["Expected risk reduction", "28%"], ["ROSI", "3.4x"],
];

const views = [
  ["Risk trend", "Enterprise risk movement over time"],
  ["Financial exposure by business unit", "Compare quantified exposure across the organization"],
  ["Top risk contributors", "Assets and scenarios driving the most exposure"],
  ["Investment vs risk reduction", "Prioritize spend with measurable risk outcomes"],
];

export default function ExecutiveDashboardPage() {
  return (
    <AppShell user={mockUser} title="Executive Dashboard" eyebrow="Business risk & financial exposure">
      <section className="technical-dashboard" aria-label="Executive business dashboard">
        <div className="dashboard-intro"><div><p className="dashboard-kicker">Understand <span>→</span> Compare <span>→</span> Decide</p><p className="dashboard-description">A boardroom-ready view of cyber risk, financial exposure and investment priorities.</p></div><span className="data-status"><span className="data-status-dot" /> Mock schema-aligned data</span></div>
        <div className="technical-kpi-grid">{kpis.map(([label, value]) => <article className="app-card technical-kpi-card" key={label}><p>{label}</p><strong>{value}</strong></article>)}</div>
        <div className="technical-view-grid">{views.map(([title, description]) => <article className="app-card technical-placeholder" key={title}><div className="placeholder-heading"><div><h2>{title}</h2><p>{description}</p></div><span className="placeholder-badge">Planned</span></div><div className="placeholder-body">This executive visualization will be connected one component at a time.</div></article>)}</div>
      </section>
    </AppShell>
  );
}
