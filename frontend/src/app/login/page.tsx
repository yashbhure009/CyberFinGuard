"use client";

import { FormEvent, useState } from "react";
import { ArrowRight, BarChart3, LockKeyhole, ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { login } from "@/lib/api";
import type { UserRole } from "@/types";

export default function LoginPage() {
  const router = useRouter();
  const [role, setRole] = useState<UserRole>("CISO");
  const [email, setEmail] = useState("alex.morgan@bankx.example");
  const [password, setPassword] = useState("password");
  const [busy, setBusy] = useState(false);
  async function submit(event: FormEvent) { event.preventDefault(); setBusy(true); const user = await login(email, password, role); sessionStorage.setItem("cyberfinguard-user", JSON.stringify(user)); router.push("/assessment"); }
  return <main className="login-page"><div className="login-brand"><div className="brand-mark brand-mark-large"><ShieldCheck size={26} /></div><div><strong>CyberFinGuard</strong><span>Continuous cyber risk quantification</span></div></div><section className="login-card app-card"><div className="login-heading"><p className="eyebrow">Secure workspace</p><h1>Make cyber risk easier to decide.</h1><p>Connect technical signals and translate them into financial exposure your teams can act on.</p></div><div className="role-toggle" role="tablist">{(["CISO", "CFO"] as UserRole[]).map((item) => <button key={item} className={role === item ? "role-active" : ""} onClick={() => setRole(item)}><span>{item === "CISO" ? <ShieldCheck size={16} /> : <BarChart3 size={16} />}</span>{item}</button>)}</div><form onSubmit={submit}><label className="form-field"><span className="field-label">Work email</span><input className="field-input" value={email} onChange={(event) => setEmail(event.target.value)} type="email" required /></label><label className="form-field"><span className="field-label">Password</span><div className="password-wrap"><input className="field-input" value={password} onChange={(event) => setPassword(event.target.value)} type="password" required /><LockKeyhole size={16} /></div></label><button className="primary-button login-submit" disabled={busy}>{busy ? "Signing in..." : "Sign in"}<ArrowRight size={16} /></button></form><p className="login-footnote">Demo mode is active. Use any valid email and password.</p></section><p className="login-footer">Protected workspace · Built for security and finance leaders</p></main>;
}
