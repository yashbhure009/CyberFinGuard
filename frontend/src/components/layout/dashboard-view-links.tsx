import Link from "next/link";

export function DashboardViewLinks() {
  return <nav className="dashboard-view-links" aria-label="Dashboard views"><span>Connected views</span><Link href="/dashboard/executive">Executive</Link><Link href="/dashboard/technical">Technical</Link><Link href="/compliance">Compliance</Link></nav>;
}
