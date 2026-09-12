"use client";

import { useState } from "react";
import { Menu } from "lucide-react";
import { Sidebar } from "@/components/layout/sidebar";
import type { User } from "@/types";

export function AppShell({ user, title, eyebrow, children }: { user: User; title: string; eyebrow?: string; children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useState(false);
  return <div className="shell">
    <Sidebar user={user} collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} />
    <main className={`main-content ${collapsed ? "main-content-wide" : ""}`}>
      <header className="topbar"><button className="mobile-menu" aria-label="Open navigation"><Menu size={20} /></button><div><p className="eyebrow">{eyebrow || "CyberFinGuard"}</p><h1>{title}</h1></div><div className="topbar-meta"><span className="online-dot" /> API connected</div></header>
      {children}
    </main>
  </div>;
}
