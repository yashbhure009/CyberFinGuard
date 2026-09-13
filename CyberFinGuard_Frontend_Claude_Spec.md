# CyberFinGuard Frontend Design & Integration Specification

## Purpose
This document is the single source of truth for building the **CyberFinGuard frontend** and preparing the **PostgreSQL schema** needed by the frontend workflow.

The security integrations, AI/ML models, and backend processing are being developed separately. Therefore:
- Keep the frontend modular and API-driven.
- Use mock data initially where backend endpoints are not ready.
- Do not tightly couple UI components to fixed model parameters.
- Preserve the existing repository structure.
- Build the website inside the existing `frontend/` folder.
- Do not replace or reorganize `backend/`, `ingestion/`, `risk_engine/`, or `ai_layer/`.

## Existing Repository Structure

```text
CyberFinGuard/
├── .vscode/
│   ├── launch.json
│   ├── settings.json
│   └── task.json
├── ai_layer/
│   └── .gitkeep
├── backend/
│   └── .gitkeep
├── frontend/
│   └── .gitkeep
├── ingestion/
│   └── .gitkeep
├── risk_engine/
│   └── .gitkeep
├── .env
├── .gitignore
└── docker-compose.yml
```

### Important
Do **not** create a new project outside this repository.

All frontend code must be created inside the existing `frontend/` folder.

Recommended resulting structure:

```text
CyberFinGuard/
├── ai_layer/
├── backend/
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   ├── components/
│   │   ├── hooks/
│   │   ├── lib/
│   │   ├── store/
│   │   └── types/
│   ├── public/
│   ├── package.json
│   ├── tsconfig.json
│   └── next.config.ts
├── ingestion/
├── risk_engine/
├── .env
├── .gitignore
└── docker-compose.yml
```

# 1. Product Name
**CyberFinGuard**

Suggested positioning:
> Continuous Cyber Risk Quantification & Decision Intelligence Platform

Design language:
- professional
- minimal
- light theme
- enterprise
- fintech + cybersecurity
- clean whitespace
- subtle interactions
- restrained animation
- polished enough for SIH demo and executive presentation

Avoid:
- hacker-style neon UI
- dark green terminal aesthetics
- excessive gradients
- glowing cards
- cluttered dashboards

# 2. Recommended Frontend Stack
Use:
```text
Next.js 16
TypeScript
Tailwind CSS
shadcn/ui
Recharts
Motion / Framer Motion
Lucide React
TanStack Query
React Hook Form
Zod
PostgreSQL
Prisma ORM
```

Notes:
- Recharts should power dashboard charts.
- Motion should be used only for subtle transitions.
- shadcn/ui should provide cards, dialogs, drawers, tabs, inputs, buttons, sheets, tables, badges, toggles, etc.
- Use TypeScript throughout.
- Keep all data fetching abstracted away from UI components.

# 3. Overall User Flow

```text
LOGIN
  ↓
HOME / ASSESSMENT SETUP
  ↓
Website Scan (ZAP)
  ↓
OpenVAS Configuration
  ↓
Prowler Configuration
  ↓
Keycloak Configuration
  ↓
Business Information
  ↓
Analyze Cyber Risk
  ↓
RISK QUANTIFICATION WORKSPACE
  ├── Quantified Risk
  ├── Vulnerability Priorities
  ├── Recommendation Engine
  └── What-if AI Assistant
  ↓
Explore Risk Intelligence
  ↓
EXECUTIVE DASHBOARD / TECHNICAL DASHBOARD
  ↓
COMPLIANCE VIEW
  ↓
PDF EXPORT
```

# 4. Authentication Page

Route:
```text
/login
```

The login page must contain a role toggle:
```text
CISO | CFO
```

Fields:
```text
Email
Password
```

CTA:
```text
Sign In
```

Behavior:
- CISO login should default toward the Technical Dashboard later.
- CFO login should default toward the Executive Dashboard later.
- Both users must still be able to access both dashboards.
- Mock authentication is acceptable initially.

# 5. Persistent App Shell

After login, authenticated pages should use the same shell.

Sidebar:
```text
CyberFinGuard

Home
Executive Dashboard
Technical Dashboard
Compliance View

Assessment Status
- Data Sources
- Business Context
- Risk Analysis

User
Role
Logout
```

Requirements:
- collapsible sidebar
- responsive
- light theme
- active navigation state
- topbar with page title and optional user metadata

# 6. Home / Assessment Setup Page

Route:
```text
/assessment
```

Header:
```text
New Cyber Risk Assessment

Connect your environment and build a continuously updated picture of cyber exposure.
```

Use a stepper:
```text
1. Website Scan
2. Network
3. Cloud
4. Identity
5. Business Context
```

Only one step should be expanded at a time.

When one step is saved successfully:
- mark it complete
- collapse it
- animate open the next step

Do not show all configuration forms expanded at once.

# 7. Step 1 - Website Scan / OWASP ZAP

UI:
```text
Website Security Scan

Website URL
[ https://example.com ]

[ Scan Website ]
```

Frontend payload:
```json
{
  "url": "https://example.com"
}
```

During scanning:
```text
Scanning website...

✓ Crawling application
✓ Discovering endpoints
● Testing application security
○ Processing findings
```

After success:
```text
✓ Website Scan Complete

27 endpoints analyzed
12 findings discovered
Last scan: ...
```

Then unlock the next step.

The frontend only sends the URL. ZAP execution belongs to the backend/integration layer.

# 8. Step 2 - Network / OpenVAS

Fields:
```text
IP Address
Port
```

CTA:
```text
Save Network Target
```

Validation:
- valid IPv4 / IPv6
- port between 1 and 65535

After save:
```text
✓ Network target configured
```

Store through the API so backend can use it for OpenVAS.

# 9. Step 3 - Cloud / Prowler

Cloud configuration must be scalable.

Suggested UI:
```text
Cloud Security Configuration

Provider
[ AWS ▼ ]

Credential Fields

[ Save Cloud Configuration ]
```

The component should be schema-driven so providers can later include:
```text
AWS
Azure
GCP
```

Recommended component:
```text
CloudCredentialForm
```

It should receive field definitions dynamically.

Credentials must not be exposed after saving.

# 10. Step 4 - Keycloak / IAM

Fields:
```text
Keycloak URL
Realm
Client ID
Client Secret
```

Example shape:
```json
{
  "url": "https://keycloak.bankx.com",
  "realm": "bankx",
  "client_id": "cyberfinguard",
  "client_secret": "xxxx-xxxx-xxxx"
}
```

CTA:
```text
Save IAM Configuration
```

After save:
```text
Client Secret
••••••••••••••••    ✓ Configured
```

Do not display the stored secret again.

# 11. Step 5 - Business Information

This data supports the Impact Model.

Suggested sections:

## Asset Information
```text
Asset Name
Asset Type
Business Unit
Asset Owner
```

## Business Importance
```text
Business Value ₹
Operational Criticality
Data Sensitivity
Service Dependency
```

## Financial Impact
```text
Estimated Downtime Cost / hour
Potential Regulatory Exposure
Estimated Recovery Cost
Revenue Dependency
```

## Criticality
```text
Asset Criticality: 1 to 5
```

CTA:
```text
Save Business Context
```

Keep this form flexible so parameters can later be added, removed, or renamed.

# 12. End of Setup

After all steps are complete:
```text
✓ Environment Connected
✓ Security Sources Configured
✓ Business Context Added

CyberFinGuard is ready to quantify your cyber exposure.

[ Analyze Cyber Risk ]
```

After risk analysis finishes:
```text
Risk analysis complete.

[ Explore Risk Intelligence → ]
```

# 13. Risk Quantification Workspace

Route:
```text
/risk-analysis
```

This page is **not another dashboard**.

It is a risk-analysis and recommendation workspace.

Recommended desktop layout:
```text
┌─────────────────────────────────────────────────────────────┐
│ Risk Quantification                         Download PDF ↓  │
├──────────────────────────────┬──────────────────────────────┤
│   RISK QUANTIFICATION        │  RECOMMENDATION ENGINE      │
│   EAL                        │  Priority 1                  │
│   VaR                        │  Vulnerability               │
│   Financial Exposure         │  Why it matters             │
│   Vulnerability Priority     │  Remediation                 │
│   Likelihood                 │  Risk reduction             │
├──────────────────────────────┴──────────────────────────────┤
│                                      [ Ask CyberFinGuard ] │
└─────────────────────────────────────────────────────────────┘
```

# 14. Risk Quantification - Left Side

Primary metrics:
```text
Expected Annual Loss
Value at Risk
Total Financial Exposure
Critical Risks
Assets at Risk
```

Also show vulnerability priority cards.

Example:
```text
Priority 1
CVE-2026-XXXX
Payment Gateway

Likelihood: 84%
Impact: ₹72L
EAL Contribution: ₹60L
```

Recommended visualization:
```text
Likelihood × Financial Impact Scatter Plot
```

Each point should represent a vulnerability/risk.

Clicking a point should select the corresponding vulnerability.

# 15. Recommendation Engine - Right Side

Use decision-oriented cards, not long AI paragraphs.

Example:
```text
Recommended Action #1

Patch CVE-2026-XXXX
Payment Gateway

Priority: CRITICAL

Why this is prioritized:
• Exploit probability: 84%
• Asset criticality: 5/5
• CISA KEV detected
• EAL contribution: ₹60L

Recommended Remediation:
1. Deploy patch
2. Validate service health
3. Re-run vulnerability scan

Expected Risk Reduction:
₹42L / year

[ Simulate Remediation ]
```

Use expandable cards if needed.

# 16. What-if AI Analyzer

Place a floating button bottom-right:
```text
✦ Ask CyberFinGuard
```

Click opens a chat drawer/panel.

Suggested questions:
```text
What if MFA is enabled for all privileged users?
What happens if this patch is delayed by 30 days?
How can I reduce EAL under ₹20L?
```

Scenario results should be visualized:
```text
Current                    Projected

Likelihood
72%              →            39%

EAL
₹1.2 Cr          →            ₹61L

Risk Reduction
₹59L
```

The chatbot is a what-if analyzer, not just generic chat.

# 17. PDF Export

Risk Analysis page should include:
```text
[ Download Risk Summary ]
```

Later the frontend can call a backend endpoint returning PDF bytes.

Suggested report:
```text
CyberFinGuard Risk Assessment
Assessment Information
Enterprise Risk Summary
EAL
VaR
Top Vulnerabilities
Top Risk Drivers
Recommended Actions
Expected Risk Reduction
Compliance Summary
Timestamp
```

# 18. Dashboard Transition

After Risk Analysis:
```text
Your current cyber exposure has been quantified.

[ Explore Risk Intelligence → ]
```

Role-based default navigation:
```text
CFO  → Executive Dashboard
CISO → Technical Dashboard
```

Both remain accessible.

# 19. Two Separate Dashboards

The platform must have **two genuinely separate dashboard pages**.

They are not two tabs of one dashboard.

Routes:
```text
/dashboard/executive
/dashboard/technical
```

Both dashboards:
- use the same shared backend/risk records
- use the same risk IDs
- may share reusable components
- can link to corresponding records in the other dashboard

Both pages should have a top switch:
```text
Executive Dashboard ↔ Technical Dashboard
```

The switch navigates to the separate route.

# 20. Executive / Business Dashboard

Route:
```text
/dashboard/executive
```

Core design principle:
> Understand → Compare → Simulate → Decide

This dashboard must be:
- highly visual
- polished
- financial
- boardroom-friendly
- executive-oriented
- interactive
- subtly animated

It should be visually more refined than the Technical Dashboard.

## KPI Row
```text
Enterprise Risk Score
Financial Exposure
Expected Annual Loss
Value at Risk
High Risk Assets
Expected Risk Reduction
ROSI
```

## Main Visualizations

### Risk Trend
Animated line / area chart.

### Financial Exposure by Business Unit
Horizontal bar chart.

### Top Risk Contributors
Ranked bar chart.

### Likelihood × Financial Impact
Heatmap or scatter-based visual.

### Investment vs Risk Reduction
Major visualization showing diminishing returns and an optimal spend region.

### Priority Actions
Display high-value mitigation actions with quantified expected risk reduction.

# 21. Executive What-if Simulator

Major interactive section.

Controls:
```text
Patch vulnerability
Enable MFA
Enable EDR
Enable WAF
Improve control
Change investment amount
```

Result:
```text
Current EAL          Projected EAL
₹2.1 Cr      →       ₹1.1 Cr

Risk Reduction
₹1.0 Cr
```

Use subtle animation when values change.

# 22. Executive Investment Optimizer

Display:
```text
Available Budget
Recommended Controls
Control Cost
Current Risk
Projected Risk
Risk Reduction
ROSI
Remaining Budget
```

Major chart:
```text
Investment vs Risk Reduction Curve
```

Highlight:
```text
Optimal Spend Zone
```

This should be interactive and visually impressive.

# 23. Technical / Security Dashboard

Route:
```text
/dashboard/technical
```

Core principle:
> Observe → Investigate → Remediate

This dashboard should be:
- dense
- operational
- evidence-oriented
- drill-down focused
- technically detailed

## KPI Row
```text
Total Findings
Critical Findings
High Findings
Unpatched Findings
Exploitable Findings
Assets Monitored
Patch Compliance %
MFA / EDR Coverage %
```

## Main Charts
```text
Findings by Severity
CVSS vs EPSS
Vulnerability Trend
Control Coverage
Top Risky Assets
```

## Main Findings Table
```text
Finding ID
Asset
CVE
CVSS
EPSS
Exploit Available
Patch Status
Control Status
Likelihood
Impact
EAL
Severity
```

Clicking a row opens a side drawer.

# 24. Technical Finding Drawer

Tabs:
```text
Overview
Threat Intelligence
Likelihood
Impact
Controls
Compliance
Recommendation
```

Suggested content:

## Threat / Vulnerability
```text
CVE
CVSS
EPSS
CISA KEV
Exploit Available
Exploit Type
Threat Actor
Malware
MITRE Technique
```

## Controls
```text
MFA
Patching
WAF
EDR
Control effectiveness
```

## Risk Output
```text
Likelihood
Impact
EAL
Risk Level
```

## Explainability
```text
Top risk drivers
```

## Compliance
```text
Framework
Control
Gap
Affected Asset
Related Finding
Priority
Remediation
Owner
Status
```

## Recommendation
Technical remediation steps.

Optional link:
```text
View Business Impact
```

This should navigate to the related executive/business context.

# 25. Compliance View

Route:
```text
/compliance
```

This is a **separate view, not a third dashboard**.

Framework selector:
```text
ISO/IEC 27001
NIST CSF
CIS Controls
RBI Cyber Security Framework
SEBI CSCRF
```

Summary cards:
```text
Compliance Posture %
Compliant Controls
Partial Controls
Control Gaps
Critical Gaps
```

Main table:
```text
Control
Framework
Status
Affected Asset
Related Finding
Severity
Remediation
Owner
Remediation Status
```

Clicking a row may open a details drawer.

# 26. Dashboard Visualization Philosophy

## Technical Dashboard
```text
Observe → Investigate → Remediate
```

Focus on:
- findings
- vulnerabilities
- technical controls
- threat intelligence
- likelihood
- remediation backlog
- framework/control mapping
- technical explainability

## Executive Dashboard
```text
Understand → Compare → Simulate → Decide
```

Focus on:
- enterprise risk
- EAL
- VaR
- financial exposure
- business-unit risk
- financial impact
- risk trends
- top contributors
- what-if simulation
- investment optimization
- ROSI
- executive recommendations

Do not make the dashboards duplicates.

# 27. Compliance Placement Philosophy

Detailed compliance belongs mainly in:
```text
Technical Dashboard
Compliance View
```

Executive Dashboard should only show concise summaries such as:
```text
Compliance Posture: 78%
Critical Framework Gaps: 5
High-Risk Controls Affected: 9
```

Do not overload the Executive Dashboard with technical control IDs.

# 28. Scalable UI Architecture

Minor parameter changes must not break the site.

Design around stable categories, not fixed fields.

Example:
```text
Finding Details
├── Vulnerability
├── Threat Intelligence
├── Controls
├── Likelihood
├── Impact
├── Compliance
└── Recommendation
```

If later new parameters are added, such as:
```text
Network Exposure
Attack Complexity
Backup Status
Control Confidence
```

insert them into the correct category without redesigning the page.

# 29. API Abstraction Layer

Do **not** place `fetch()` calls randomly inside cards or chart components.

Create:
```text
frontend/src/lib/api.ts
```

Suggested functions:
```text
login()
scanWebsite()
saveNetworkTarget()
saveCloudIntegration()
saveKeycloakIntegration()
saveBusinessContext()

getRiskAnalysis()
getExecutiveDashboard()
getTechnicalDashboard()
getComplianceData()

runScenario()
getRecommendations()
downloadRiskSummary()
```

Initially these may return mock data.

Later replace the implementation with real backend API calls without changing UI components.

# 30. Suggested Frontend Folder Structure

Inside the existing `frontend/` directory:

```text
frontend/
├── src/
│   ├── app/
│   │   ├── login/
│   │   │   └── page.tsx
│   │   ├── assessment/
│   │   │   └── page.tsx
│   │   ├── risk-analysis/
│   │   │   └── page.tsx
│   │   ├── dashboard/
│   │   │   ├── executive/
│   │   │   │   └── page.tsx
│   │   │   └── technical/
│   │   │       └── page.tsx
│   │   └── compliance/
│   │       └── page.tsx
│   ├── components/
│   │   ├── layout/
│   │   │   ├── app-shell.tsx
│   │   │   ├── sidebar.tsx
│   │   │   └── topbar.tsx
│   │   ├── assessment/
│   │   │   ├── assessment-stepper.tsx
│   │   │   ├── website-scan.tsx
│   │   │   ├── network-config.tsx
│   │   │   ├── cloud-config.tsx
│   │   │   ├── keycloak-config.tsx
│   │   │   └── business-context.tsx
│   │   ├── risk/
│   │   │   ├── risk-summary.tsx
│   │   │   ├── vulnerability-priority.tsx
│   │   │   ├── recommendation-engine.tsx
│   │   │   └── what-if-assistant.tsx
│   │   ├── executive/
│   │   ├── technical/
│   │   ├── compliance/
│   │   ├── charts/
│   │   └── ui/
│   ├── hooks/
│   ├── lib/
│   │   ├── api.ts
│   │   ├── validators.ts
│   │   ├── formatters.ts
│   │   └── mock-data.ts
│   ├── store/
│   └── types/
├── public/
├── package.json
└── ...
```

Do not modify other top-level system folders unless explicitly requested.

# 31. PostgreSQL Setup

The database schema can evolve later through migrations.

Recommended starter tables:
```text
users
assessments
website_targets
network_targets
cloud_integrations
iam_integrations
assets
findings
risk_results
recommendations
compliance_mappings
scenario_results
```

Suggested high-level schema:

## users
```text
id
email
password_hash
role
created_at
```

## assessments
```text
id
user_id
organization_name
status
created_at
updated_at
```

## website_targets
```text
id
assessment_id
url
scan_status
last_scanned_at
```

## network_targets
```text
id
assessment_id
ip_address
port
created_at
```

## cloud_integrations
```text
id
assessment_id
provider
credential_reference
status
```

## iam_integrations
```text
id
assessment_id
keycloak_url
realm
client_id
secret_reference
status
```

## assets
```text
id
assessment_id
asset_name
asset_type
business_unit
owner
business_value
data_sensitivity
operational_criticality
service_dependency
asset_criticality
```

## findings
```text
id
assessment_id
asset_id
source
cve_id
cvss
epss
severity
exploit_available
patch_status
raw_data
created_at
```

## risk_results
```text
id
finding_id
likelihood
financial_impact
eal
var
risk_score
risk_level
model_version
calculated_at
```

## recommendations
```text
id
finding_id
priority
recommendation
estimated_risk_reduction
estimated_cost
status
```

## compliance_mappings
```text
id
finding_id
framework
control_id
status
gap
remediation
```

## scenario_results
```text
id
assessment_id
scenario
baseline_eal
projected_eal
risk_reduction
created_at
```

Use `JSONB` where flexible integration-specific metadata is expected.

# 32. Security Handling for Credentials

Do not store sensitive secrets as plain text.

Sensitive fields:
```text
Keycloak client secret
Cloud credentials
API keys
Tokens
```

For prototype/mock mode, forms may simulate saving.

For actual implementation:
- encrypt credentials before persistence, or
- store them in a secrets manager and persist only a reference

Never return saved secrets to the frontend.

# 33. Chart / Interaction Guidance

Use Recharts with polished wrappers.

Recommended charts:
```text
Line / Area
- Risk Trend
- Vulnerability Trend

Horizontal Bar
- Top Risk Contributors
- Financial Exposure by Business Unit
- Top Risky Assets

Scatter
- CVSS vs EPSS
- Likelihood vs Financial Impact

Donut / Bar
- Severity distribution
- Control coverage

Curve / Line
- Investment vs Risk Reduction
```

Interactions:
- chart tooltips
- click chart item to filter/select
- selected risk opens drawer
- animated number transitions
- subtle chart entry animation
- scenario before/after transitions
- drawer slide animation

Keep animation duration around:
```text
150–300ms
```

No excessive motion.

# 34. Visual Design Tokens

Suggested design direction:
```text
Background: soft neutral / off-white
Cards: white
Borders: light neutral
Text: charcoal / near-black
Primary accent: one restrained enterprise accent
Critical: muted red
High: muted orange
Medium: muted amber
Low: muted green
```

Cards:
```text
10–14px radius
subtle borders
minimal shadows
```

Typography:
- clear
- modern
- enterprise
- strong hierarchy
- avoid oversized marketing text inside dashboards

# 35. Responsive Behavior

Desktop is primary for the SIH demo, but the site should behave properly on smaller screens.

Requirements:
- collapsible sidebar
- stacked KPI cards on narrow widths
- scrollable data tables
- chart resizing
- responsive forms
- drawers/sheets instead of fixed panels when space is limited

# 36. Mock Data First, Real Backend Later

The frontend should be fully demonstrable before backend integration.

Use:
```text
frontend/src/lib/mock-data.ts
```

for:
```text
website scan progress
technical findings
risk metrics
executive metrics
recommendations
compliance status
scenario results
investment optimization values
```

All mock data access should still pass through the same API abstraction layer.

Later:
```text
mock implementation
        ↓
real backend API
```

without changing presentation components.

# 37. State Management

Use local component state for simple forms.

Use shared state only for:
```text
current assessment ID
logged-in user
selected role
assessment progress
selected finding
dashboard filters
```

Do not over-engineer global state.

# 38. Data Types

Create reusable TypeScript types/interfaces for:
```text
User
Assessment
WebsiteTarget
NetworkTarget
CloudIntegration
IAMIntegration
Asset
Finding
RiskResult
Recommendation
ComplianceMapping
ScenarioResult
ExecutiveDashboardData
TechnicalDashboardData
```

Do not use `any` unnecessarily.

# 39. Error / Loading / Empty States

Every asynchronous action should have:
```text
loading state
success state
error state
empty state
```

Examples:
```text
Scanning website...
Scan complete
Scan failed
No findings available
No risk results yet
No compliance data available
```

Use skeleton loaders where appropriate.

# 40. Important Development Rules

Claude should follow these rules strictly:

1. Keep the current repository structure.
2. Build all website code under `frontend/`.
3. Do not rewrite `backend/`, `ingestion/`, `risk_engine/`, or `ai_layer/`.
4. Use modular React components.
5. Use TypeScript.
6. Keep API calls centralized.
7. Use mock data initially.
8. Keep model parameters flexible.
9. Maintain two separate dashboard routes.
10. Executive and Technical dashboards must not become duplicates.
11. Keep Compliance as a separate view, not a third dashboard.
12. Use PostgreSQL schema that can evolve through migrations.
13. Use JSONB only where flexible metadata is appropriate.
14. Never expose saved secrets back to the UI.
15. Keep the visual design light, minimal, professional, and enterprise-ready.
16. Use subtle interaction rather than excessive animation.
17. Every page should be responsive.
18. Keep the code easy for backend teammates to integrate later.

# 41. Suggested Development Order

```text
1. Initialize Next.js frontend inside existing frontend/
2. Set up Tailwind + shadcn/ui
3. Create app shell
4. Create login page
5. Create assessment stepper
6. Build ZAP website scan UI
7. Build OpenVAS network config UI
8. Build Prowler cloud config UI
9. Build Keycloak config UI
10. Build Business Context form
11. Build mock API layer
12. Build Risk Quantification workspace
13. Build Recommendation Engine
14. Build What-if Assistant
15. Build Executive Dashboard
16. Build Technical Dashboard
17. Build Compliance View
18. Add cross-dashboard navigation
19. Add PDF download UI
20. Add PostgreSQL + Prisma schema
21. Add mock persistence / API stubs
22. Polish loading/error states
23. Add responsive behavior
24. Add subtle animations
25. Final integration cleanup
```

# 42. Final Product Principle

The product should communicate one continuous story:

```text
Technical telemetry
        ↓
Risk likelihood
        ↓
Business impact
        ↓
Financial risk
        ↓
Prioritized action
        ↓
Risk reduction
        ↓
Better cyber investment decision
```

The two dashboards must preserve their distinct purposes:

```text
Technical Dashboard
Observe → Investigate → Remediate

Executive Dashboard
Understand → Compare → Simulate → Decide
```

# 43. Final Instruction to Claude

Build CyberFinGuard as a production-quality, light-theme enterprise cybersecurity analytics frontend using Next.js, TypeScript, Tailwind, shadcn/ui, Recharts, and Motion.

The backend security integrations and ML models are being developed independently, so all frontend components must be API-driven, modular, and capable of initially operating on mock data.

Do not tightly couple UI components to a fixed set of model parameters.

Maintain two genuinely separate dashboard pages:
- Executive Dashboard
- Technical Dashboard

The Executive Dashboard must follow:
```text
Understand → Compare → Simulate → Decide
```
and must be highly visual, financial, interactive, and business-oriented.

The Technical Dashboard must follow:
```text
Observe → Investigate → Remediate
```
and must be dense, investigative, technically detailed, and finding/control-oriented.

Compliance is a separate view, not a third dashboard.

Preserve the existing repository structure and build all frontend files inside the current `frontend/` directory.

Keep the frontend clean so real backend endpoints, security integration results, database values, AI/ML outputs, and recommendation APIs can be connected later without redesigning the UI.
