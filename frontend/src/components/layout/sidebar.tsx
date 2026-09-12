"use client";

import Link from "next/link";
import { BarChart3, CheckCircle2, ChevronLeft, ClipboardCheck, FileCheck2, Home, LogOut, ShieldCheck, UserRound } from "lucide-react";
import { usePathname } from "next/navigation";
import type { User } from "@/types";

const navigation = [
  { label: "Home", href: "/assessment", icon: Home },
  { label: "Executive Dashboard", href: "/dashboard/executive", icon: BarChart3 },
  { label: "Technical Dashboard", href: "/dashboard/technical", icon: ShieldCheck },
  { label: "Compliance View", href: "/compliance", icon: FileCheck2 },
];

export function Sidebar({ user, collapsed, onToggle }: { user: User; collapsed: boolean; onToggle: () => void }) {
  const pathname = usePathname();
  return (
    <aside className={`sidebar ${collapsed ? "sidebar-collapsed" : ""}`}>
      <div className="sidebar-brand">
        <div className="brand-mark"><ShieldCheck size={19} /></div>
        {!collapsed && <div><strong>CyberFinGuard</strong><span>Risk intelligence</span></div>}
        <button className="sidebar-toggle" onClick={onToggle} aria-label="Toggle sidebar"><ChevronLeft size={16} className={collapsed ? "rotate-180" : ""} /></button>
      </div>
      <nav className="sidebar-nav">
        {!collapsed && <p className="nav-label">Workspace</p>}
        {navigation.map(({ label, href, icon: Icon }) => {
          const active = pathname === href;
          return <Link className={`nav-link ${active ? "nav-link-active" : ""}`} href={href} key={href} title={collapsed ? label : undefined}><Icon size={17} />{!collapsed && <span>{label}</span>}</Link>;
        })}
      </nav>
      {!collapsed && <div className="assessment-status">
        <p className="nav-label">Assessment status</p>
        <div className="status-item status-done"><CheckCircle2 size={15} /><span>Data sources</span><small>1/4</small></div>
        <div className="status-item"><ClipboardCheck size={15} /><span>Business context</span><small>2/4</small></div>
        <div className="status-item"><BarChart3 size={15} /><span>Risk analysis</span><small>3/4</small></div>
      </div>}
      <div className="sidebar-user">
        <div className="avatar"><UserRound size={16} /></div>
        {!collapsed && <div className="user-copy"><strong>{user.name}</strong><span>{user.role}</span></div>}
        {!collapsed && <button className="logout-button" aria-label="Log out"><LogOut size={15} /></button>}
      </div>
    </aside>
  );
}
