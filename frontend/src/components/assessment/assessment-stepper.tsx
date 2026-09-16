"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Check, ChevronDown, Cloud, Globe2, Landmark, LockKeyhole, Save, ShieldCheck } from "lucide-react";
import { saveBusinessContext, saveCloudIntegration, saveKeycloakIntegration, saveWebsiteTarget, runScan, collectIntegration } from "@/lib/api";
import { cloudCredentialFields } from "@/lib/mock-data";
import { websiteSchema } from "@/lib/validators";
import type { AssessmentProgress, CloudIntegration, User } from "@/types";

type Step = { title: string; description: string; icon: typeof Globe2 };
const steps: Step[] = [
  { title: "Website scan", description: "Discover application exposure with an OWASP ZAP scan.", icon: Globe2 },
  { title: "Cloud", description: "Connect a cloud account using least-privilege access.", icon: Cloud },
  { title: "Identity", description: "Connect Keycloak to understand IAM posture.", icon: LockKeyhole },
  { title: "Business context", description: "Translate technical exposure into business impact.", icon: Landmark },
];

export function AssessmentStepper({ user }: { user: User }) {
  const router = useRouter();
  const [activeStep, setActiveStep] = useState(0);
  const [completed, setCompleted] = useState<number[]>([]);
  const [progress, setProgress] = useState<AssessmentProgress>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [website, setWebsite] = useState("https://example.com");
  const [cloud, setCloud] = useState<CloudIntegration>({ provider: "AWS", fields: { accountId: "", roleArn: "" }, status: "pending" });
  const [iam, setIam] = useState({ url: "", realm: "", clientId: "", clientSecret: "" });
  const [business, setBusiness] = useState({
    assetName: "Payment Gateway",
    assetType: "Application",
    businessUnit: "Digital Banking",
    assetOwner: user.name,
    businessValue: "50000000",
    operationalCriticality: "5",
    dataSensitivity: "Highly sensitive",
    serviceDependency: "Critical",
    downtimeCostPerHour: "250000",
    regulatoryExposure: "10000000",
    recoveryCost: "5000000",
    revenueDependency: "70",
    assetCriticality: "5",
  });

  function openNext() {
    setCompleted((current) => (current.includes(activeStep) ? current : [...current, activeStep]));
    setActiveStep((current) => Math.min(current + 1, steps.length - 1));
    setError("");
  }

  async function handleSave() {
    setBusy(true);
    setError("");
    try {
      if (activeStep === 0) {
        const parsed = websiteSchema.safeParse({ url: website });
        if (!parsed.success) throw new Error(parsed.error.issues[0].message);
        const result = await saveWebsiteTarget({ url: website, scanStatus: "scanning" });
        // Trigger backend ZAP scan if authorized target
        try {
          await runScan(website, ["zap"]);
        } catch (scanErr) {
          console.warn("Scan initiation note:", scanErr);
        }
        setProgress((p) => ({ ...p, website: result }));
      }
      if (activeStep === 1) {
        const hasCloudFields = Object.values(cloud.fields).some((value) => value.trim());
        if (hasCloudFields) {
          const result = await saveCloudIntegration(cloud);
          try {
            await collectIntegration("prowler");
          } catch (cloudErr) {
            console.warn("Cloud collection note:", cloudErr);
          }
          setProgress((p) => ({ ...p, cloud: result }));
        }
      }
      if (activeStep === 2) {
        if (!iam.url || !iam.realm || !iam.clientId || !iam.clientSecret)
          throw new Error("Complete all identity fields before saving.");
        const result = await saveKeycloakIntegration({
          url: iam.url,
          realm: iam.realm,
          clientId: iam.clientId,
          clientSecret: iam.clientSecret,
          status: "configured",
        });
        try {
          await collectIntegration("keycloak");
        } catch (iamErr) {
          console.warn("Keycloak collection note:", iamErr);
        }
        setIam((current) => ({ ...current, clientSecret: "" }));
        setProgress((p) => ({ ...p, iam: result }));
      }
      if (activeStep === 3) {
        const result = await saveBusinessContext({
          ...business,
          businessValue: Number(business.businessValue),
          operationalCriticality: Number(business.operationalCriticality),
          downtimeCostPerHour: Number(business.downtimeCostPerHour),
          regulatoryExposure: Number(business.regulatoryExposure),
          recoveryCost: Number(business.recoveryCost),
          revenueDependency: Number(business.revenueDependency),
          assetCriticality: Number(business.assetCriticality),
        });
        setProgress((p) => ({ ...p, business: result }));
      }
      openNext();
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : "Unable to save this step.");
    } finally {
      setBusy(false);
    }
  }

  const input = (label: string, value: string, onChange: (value: string) => void, type = "text", key?: string) => (
    <label className="form-field" key={key}>
      <span className="field-label">{label}</span>
      <input className="field-input" type={type} value={value} onChange={(event) => onChange(event.target.value)} />
    </label>
  );

  return (
    <div className="assessment-layout">
      <div className="stepper-column">
        {steps.map((step, index) => {
          const Icon = step.icon;
          const isActive = activeStep === index;
          const isDone = completed.includes(index);
          return (
            <div className={`step-row ${isActive ? "step-active" : ""}`} key={step.title}>
              <div className={`step-number ${isDone ? "step-number-done" : ""}`}>
                {isDone ? <Check size={15} /> : index + 1}
              </div>
              <div className="step-line-content">
                <button className="step-heading" onClick={() => setActiveStep(index)}>
                  <span>
                    <Icon size={17} />
                    {step.title}
                  </span>
                  <ChevronDown size={16} className={isActive ? "chevron-open" : ""} />
                </button>
                <p>{step.description}</p>
                {isActive && (
                  <div className="step-form">
                    {index === 0 && (
                      <>
                        <div className="scan-callout">
                          <ShieldCheck size={18} />
                          <span>We only send the target. Scanning runs securely through your connected environment.</span>
                        </div>
                        {input("Website URL or IP address", website, setWebsite)}
                        <button className="primary-button" onClick={handleSave} disabled={busy}>
                          <Globe2 size={16} />
                          {busy ? "Scanning target..." : "Scan target"}
                        </button>
                      </>
                    )}
                    {index === 1 && (
                      <>
                        <label className="form-field">
                          <span className="field-label">Provider (optional)</span>
                          <select
                            className="field-input"
                            value={cloud.provider}
                            onChange={(event) =>
                              setCloud({ provider: event.target.value as CloudIntegration["provider"], fields: {}, status: "pending" })
                            }
                          >
                            <option>AWS</option>
                            <option>Azure</option>
                            <option>GCP</option>
                          </select>
                        </label>
                        <div className="form-grid">
                          {cloudCredentialFields[cloud.provider].map((field) =>
                            input(
                              `${field.label} (optional)`,
                              cloud.fields[field.key] || "",
                              (value) => setCloud({ ...cloud, fields: { ...cloud.fields, [field.key]: value } }),
                              field.type,
                              field.key,
                            ),
                          )}
                        </div>
                        <p className="form-hint">Cloud configuration is optional. Leave all fields blank to continue.</p>
                        <button className="primary-button" onClick={handleSave} disabled={busy}>
                          <Cloud size={16} />
                          Continue
                        </button>
                      </>
                    )}
                    {index === 2 && (
                      <>
                        <div className="form-grid">
                          {input("Keycloak URL", iam.url, (value) => setIam({ ...iam, url: value }))}
                          {input("Realm", iam.realm, (value) => setIam({ ...iam, realm: value }))}
                          {input("Client ID", iam.clientId, (value) => setIam({ ...iam, clientId: value }))}
                          {input("Client secret", iam.clientSecret, (value) => setIam({ ...iam, clientSecret: value }), "password")}
                        </div>
                        <button className="primary-button" onClick={handleSave} disabled={busy}>
                          <LockKeyhole size={16} />
                          Save IAM configuration
                        </button>
                      </>
                    )}
                    {index === 3 && (
                      <>
                        <div className="form-grid">{input("Asset name", business.assetName, (value) => setBusiness({ ...business, assetName: value }))}</div>
                        <div className="form-grid">
                          {input("Asset type", business.assetType, (value) => setBusiness({ ...business, assetType: value }))}
                          {input("Business unit", business.businessUnit, (value) => setBusiness({ ...business, businessUnit: value }))}
                          {input("Asset owner", business.assetOwner, (value) => setBusiness({ ...business, assetOwner: value }))}
                          {input("Business value (₹)", business.businessValue, (value) => setBusiness({ ...business, businessValue: value }), "number")}
                          {input("Downtime cost / hour (₹)", business.downtimeCostPerHour, (value) => setBusiness({ ...business, downtimeCostPerHour: value }), "number")}
                          {input("Recovery cost (₹)", business.recoveryCost, (value) => setBusiness({ ...business, recoveryCost: value }), "number")}
                        </div>
                        <button className="primary-button" onClick={handleSave} disabled={busy}>
                          <Save size={16} />
                          Save business context
                        </button>
                      </>
                    )}
                    {error && <p className="error-text">{error}</p>}
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
      <aside className="setup-summary app-card">
        <div className="summary-icon">
          <ShieldCheck size={21} />
        </div>
        <p className="eyebrow">Assessment readiness</p>
        <h2>{completed.length === steps.length ? "Environment connected" : "Build your risk picture"}</h2>
        <p>Connect the signals that help CyberFinGuard turn telemetry into an actionable financial risk view.</p>
        <div className="summary-progress">
          <div>
            <span>Setup progress</span>
            <strong>{Math.round((completed.length / steps.length) * 100)}%</strong>
          </div>
          <div className="progress-track">
            <span style={{ width: `${(completed.length / steps.length) * 100}%` }} />
          </div>
        </div>
        {completed.length === steps.length ? (
          <button
            className="primary-button"
            onClick={() => {
              const assetIds = Object.values(progress)
                .map((item) => item?.assetId)
                .filter(Boolean)
                .join(",");
              router.push(assetIds ? `/dashboard/technical?assetIds=${encodeURIComponent(assetIds)}` : "/dashboard/technical");
            }}
          >
            View Technical Dashboard <ShieldCheck size={16} />
          </button>
        ) : (
          <div className="summary-note">
            <Check size={15} /> Security tool telemetry is live
          </div>
        )}
      </aside>
    </div>
  );
}
