"use client";

import { useState, type FormEvent } from "react";
import { Bot, Send, Sparkles, X } from "lucide-react";
import { queryAssistant, type AssistantAskResponse, type AssistantMode, type AssistantSimulationResponse } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

type Message = { role: "user" | "assistant"; content: string; groundedIn?: string[] };

const numericValue = (value: number | string | null | undefined) => {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : null;
};
const money = (value: number | string | null | undefined) => {
  const parsed = numericValue(value);
  return parsed === null ? "Pending" : new Intl.NumberFormat("en-US", { style: "currency", currency: "USD", maximumFractionDigits: 0 }).format(parsed);
};
const percent = (value: number | string | null | undefined) => {
  const parsed = numericValue(value);
  return parsed === null ? "Pending" : `${parsed.toFixed(1)}%`;
};

export function AssistantWidget() {
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<AssistantMode>("ask");
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState<Message[]>([]);
  const [scenarioType, setScenarioType] = useState<"enforce_mfa" | "delay_remediation" | "free_text">("enforce_mfa");
  const [scope, setScope] = useState<"all_privileged" | "all_assets">("all_assets");
  const [days, setDays] = useState("30");
  const [simulation, setSimulation] = useState<AssistantSimulationResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    const text = question.trim();
    if (!text && mode === "ask") return;
    setLoading(true);
    setError(null);
    try {
      if (mode === "ask") {
        setMessages((current) => [...current, { role: "user", content: text }]);
        setQuestion("");
        const result = await queryAssistant("ask", { question: text });
        const response = result as AssistantAskResponse;
        setMessages((current) => [...current, { role: "assistant", content: response.answer, groundedIn: response.groundedIn }]);
      } else {
        const scenario = scenarioType === "free_text"
          ? { type: "free_text", params: { question: text } }
          : scenarioType === "enforce_mfa"
            ? { type: scenarioType, params: { scope } }
            : { type: scenarioType, params: { days: Number(days) } };
        const result = await queryAssistant("simulate", { question: text || `Simulate ${scenarioType}`, scenario });
        setSimulation(result as AssistantSimulationResponse);
      }
    } catch (requestError) {
      setError(requestError instanceof Error && requestError.message.includes("not configured") ? "AI assistant not configured yet." : requestError instanceof Error ? requestError.message : "Assistant request failed.");
    } finally {
      setLoading(false);
    }
  };

  return <>
    {!open && <Button type="button" onClick={() => setOpen(true)} className="assistant-fab" aria-label="Open CyberRobo assistant" title="CyberRobo"><span className="assistant-fab-glow" /><Bot size={30} strokeWidth={1.8} /><span className="assistant-fab-name">CyberRobo</span></Button>}
    {open && <Card className="assistant-panel">
      <CardHeader className="assistant-header"><div className="assistant-brand"><span className="assistant-avatar"><Bot size={21} /></span><div><CardTitle>CyberRobo <Sparkles size={15} /></CardTitle><p>Your grounded cyber-risk copilot.</p></div></div><Button type="button" variant="ghost" size="icon-sm" onClick={() => setOpen(false)} aria-label="Close assistant"><X size={17} /></Button></CardHeader>
      <div className="assistant-mode-toggle" role="tablist" aria-label="Assistant mode"><button type="button" className={mode === "ask" ? "assistant-mode-active" : ""} onClick={() => { setMode("ask"); setError(null); }}>Ask</button><button type="button" className={mode === "simulate" ? "assistant-mode-active" : ""} onClick={() => { setMode("simulate"); setError(null); }}>Simulate</button></div>
      <CardContent className="assistant-content">
        {mode === "ask" ? <div className="assistant-messages">{messages.length === 0 && <p className="assistant-empty">Ask CyberRobo any cybersecurity question, or ask about your dashboard data.</p>}{messages.map((message, index) => <div className={`assistant-message assistant-message-${message.role}`} key={`${message.role}-${index}`}><p>{message.content}</p>{message.groundedIn && message.groundedIn.length > 0 && <small>Basis: {message.groundedIn.join(" · ")}</small>}</div>)}</div> : <div className="assistant-simulation">
          <div className="assistant-illustrative-badge">Illustrative estimate · rules-based discussion aid</div>
          <label>Scenario<select value={scenarioType} onChange={(event) => setScenarioType(event.target.value as typeof scenarioType)}><option value="enforce_mfa">Enforce MFA</option><option value="delay_remediation">Delay remediation</option><option value="free_text">Other what-if question</option></select></label>
          {scenarioType === "enforce_mfa" && <label>Scope<select value={scope} onChange={(event) => setScope(event.target.value as typeof scope)}><option value="all_assets">All assets</option><option value="all_privileged">All privileged assets</option></select></label>}
          {scenarioType === "delay_remediation" && <label>Delay days<input type="number" min="0" value={days} onChange={(event) => setDays(event.target.value)} /></label>}
          {scenarioType === "free_text" && <label>What-if question<textarea value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="What if we..." /></label>}
          {simulation && <div className="assistant-result"><p>{simulation.scenarioSummary}</p><div className="assistant-before-after"><span>Baseline<strong>{money(simulation.baselineAle)}</strong></span><span>Simulated<strong>{money(simulation.simulatedAle)}</strong></span><span>Change<strong>{percent(simulation.deltaPercent)}</strong></span></div><strong>Assumptions</strong><ul>{simulation.assumptions.map((assumption) => <li key={assumption}>{assumption}</li>)}</ul></div>}
        </div>}
        {error && <p className="assistant-error">{error}</p>}
        {loading && <p className="assistant-loading">Working…</p>}
        <form className="assistant-form" onSubmit={submit}><input value={question} onChange={(event) => setQuestion(event.target.value)} placeholder={mode === "ask" ? "Ask a risk question…" : "Optional scenario context…"} aria-label={mode === "ask" ? "Ask a risk question" : "Scenario context"} /><Button type="submit" size="icon" disabled={loading || (mode === "ask" && !question.trim())} aria-label="Send assistant request"><Send size={16} /></Button></form>
      </CardContent>
    </Card>}
  </>;
}
