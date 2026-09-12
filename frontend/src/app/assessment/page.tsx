"use client";

import { useEffect, useState } from "react";
import { ArrowRight, ShieldCheck } from "lucide-react";
import { AppShell } from "@/components/layout/app-shell";
import { AssessmentStepper } from "@/components/assessment/assessment-stepper";
import { mockUser } from "@/lib/mock-data";
import type { User } from "@/types";

export default function AssessmentPage() {
  const [user, setUser] = useState<User>(mockUser);
  useEffect(() => { const stored = sessionStorage.getItem("cyberfinguard-user"); if (stored) setUser(JSON.parse(stored) as User); }, []);
  return <AppShell user={user} eyebrow="New assessment" title="Connect your environment"><div className="page-intro"><div><p className="intro-lead">New cyber risk assessment</p><p>Connect your environment and build a continuously updated picture of cyber exposure.</p></div><div className="intro-actions"><span className="assessment-id"><ShieldCheck size={15} /> Assessment #001</span><button className="secondary-button">View guide <ArrowRight size={15} /></button></div></div><AssessmentStepper user={user} /></AppShell>;
}
