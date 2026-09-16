# CyberFinGuard Spec Reconciliation Report

## Scope

This report compares the intended frontend/database specification in
`CyberFinGuard_Frontend_Claude_Spec.md` with the repository state at audit time.
No application code or schema was changed.

## 1. Database schema diff

### Authoritative implementation

The active schema is defined by `setup_db.py` and uses PostgreSQL through
`psycopg2`. There are no Prisma files, migrations, ORM models, or
`assessment_id` columns in the active implementation.

### Actual tables

| Table | Columns | Relationships |
|---|---|---|
| `assets` | `asset_id` PK, `asset_name`, `asset_type`, `ip_address`, `hostname`, `application`, `business_unit`, `owner`, `environment`, `internet_exposed`, `production_status`, `criticality`, `data_type`, `dependencies` text[], `asset_value`, `discovered_at`, `updated_at` | Root entity |
| `findings` | `finding_id` PK, `asset_id`, `source`, `cve_id`, `cvss_score`, `epss_score`, `cisa_kev`, `exploit_available`, `exploit_type`, `mitre_technique`, `title`, `description`, `severity`, `raw_data` JSONB, `created_at`, `updated_at` | FK `asset_id -> assets.asset_id`, cascade delete |
| `asset_controls` | `asset_id` PK, `mfa_enabled`, `patching_status`, `waf_enabled`, `edr_enabled`, `firewall_enabled`, `encryption_enabled`, `backup_exists`, `updated_at` | FK `asset_id -> assets.asset_id`, cascade delete |
| `risk_scores` | `risk_id` PK, `asset_id`, `finding_id`, `sle`, `aro`, `ale`, `likelihood_score`, `impact_score`, `calculated_at` | FKs to `assets` and `findings`, cascade delete |
| `investment_recommendations` | `recommendation_id` PK, `asset_id`, `control_name`, `investment_cost`, `risk_reduction`, `roi`, `priority`, `created_at` | FK `asset_id -> assets.asset_id`, cascade delete |

### Spec table comparison

| Spec table | Actual state | Verdict |
|---|---|---|
| `users` | No table or user persistence | Does not exist |
| `assessments` | No table | Does not exist |
| `website_targets` | Website submissions are stored as rows in `assets` with `asset_type='website'` | Different name/shape |
| `network_targets` | Network submissions are stored in `assets` with `asset_type='network_target'`; port is currently unmapped | Different name/shape |
| `cloud_integrations` | Cloud submissions become `assets` with `asset_type='cloud_account'`; fields are not persisted | Different name/shape |
| `iam_integrations` | IAM submissions become `assets` with `asset_type='iam'`; credentials are intentionally not persisted | Different name/shape |
| `assets` | Exists, but without `assessment_id` and with a broader/older shape | Exists under different shape |
| `findings` | Exists, but has no `assessment_id` or `patch_status`; uses `cvss_score`, `epss_score`, and extra fields | Exists under different shape |
| `risk_results` | Closest equivalent is `risk_scores` | Different name/shape |
| `recommendations` | Closest equivalent is `investment_recommendations` | Different name/shape |
| `compliance_mappings` | No table | Does not exist |
| `scenario_results` | No table | Does not exist |

There is no assessment/session/tenant boundary. All assets, findings, scores, and
recommendations are globally scoped. The API even contains a TODO to add
authenticated-principal scoping.

The actual `findings` table does not match the specification's proposed shape:
it lacks `id`, `assessment_id`, and `patch_status`; uses `finding_id`,
`cvss_score`, and `epss_score`; and adds `cisa_kev`, exploit metadata,
MITRE metadata, title, and description.

The repository uses direct SQL with `psycopg2` and a lazy
`ThreadedConnectionPool`. The spec assumes Prisma. Moving to the spec would
require a new Prisma schema, migrations, connection configuration, and a
repository/API rewrite.

## 2. Folder and routing structure diff

Actual frontend structure, excluding generated/build and nested reference content:

```
frontend/
├── package.json
├── next.config.ts
├── tsconfig.json
├── src/
│   ├── app/
│   │   ├── globals.css
│   │   ├── layout.tsx
│   │   ├── page.tsx
│   │   ├── placeholder-pages.tsx
│   │   ├── shell.css
│   │   ├── assessment/page.tsx
│   │   ├── dashboard/technical/page.tsx
│   │   └── login/
│   │       ├── layout.tsx
│   │       ├── login.css
│   │       └── page.tsx
│   ├── components/
│   │   ├── assessment/assessment-stepper.tsx
│   │   ├── layout/app-shell.tsx
│   │   ├── layout/sidebar.tsx
│   │   └── technical/technical-dashboard-section.tsx
│   ├── lib/
│   │   ├── api.ts
│   │   ├── formatters.ts
│   │   ├── mock-data.ts
│   │   └── validators.ts
│   └── types/index.ts
```

The `src/app` wrapper exists and the implemented route names use the Next.js
App Router. Missing spec structures include `risk-analysis/`,
`dashboard/executive/`, `compliance/`, and component groups for risk,
executive, compliance, charts, and shared UI. `placeholder-pages.tsx` exists
but is not equivalent to completed route implementations.

## 3. Feature and route coverage

| Route | State | Data source |
|---|---|---|
| `/login` | Implemented visual login page | Demo/mock login; no backend authentication |
| `/assessment` | Implemented | Real POST calls through `lib/api.ts` |
| `/risk-analysis` | Missing; no route found | None |
| `/dashboard/executive` | Missing; no route found | None |
| `/dashboard/technical` | Present, partial dashboard implementation | Current component is primarily presentation/mock-oriented |
| `/compliance` | Missing; no route found | None |

The assessment flow has exactly five steps and only one active step at a time:
Website Scan, Network, Cloud, Identity, and Business Context. It uses local
React state and advances after successful API calls. It is not backed by an
assessment record, so progress is lost on reload and cannot be isolated per
user or organization.

## 4. API abstraction layer diff

The fetch abstraction is centralized in `frontend/src/lib/api.ts`. Components
call named helpers rather than placing raw fetch calls inside the stepper.

| Spec function | Actual state |
|---|---|
| `login()` | Exists, but returns mock data |
| `scanWebsite()` | Missing; closest is `saveWebsiteTarget()` |
| `saveNetworkTarget()` | Exists |
| `saveCloudIntegration()` | Exists |
| `saveKeycloakIntegration()` | Exists |
| `saveBusinessContext()` | Exists |
| `getRiskAnalysis()` | Missing |
| `getExecutiveDashboard()` | Missing |
| `getTechnicalDashboard()` | Missing |
| `getComplianceData()` | Missing |
| `runScenario()` | Missing |
| `getRecommendations()` | Missing |
| `downloadRiskSummary()` | Missing |

Implemented backend endpoints are:

- `GET /health`
- `POST /api/assets/website`
- `POST /api/assets/network`
- `POST /api/assets/cloud`
- `POST /api/assets/iam`
- `POST /api/assets/business-context`
- `GET /api/assets/{asset_id}`

The implemented website form was verified to create an `assets` row. The API
returns unmapped fields for values that are accepted by the UI but are not yet
stored, such as the URL, network port, and several business-context fields.

## 5. Backend diff and known risks

FastAPI is present and is backed by PostgreSQL through `psycopg2`. The
database pool is lazy, so importing the backend does not immediately connect.

Current limitations and risks:

- Authentication is not implemented. The frontend login is demo-only.
- The repository is globally scoped; there is no tenant or assessment isolation.
- IAM client secrets are accepted as `SecretStr` but deliberately discarded;
  a production implementation needs a secrets manager and a non-secret reference.
- Cloud credential fields are accepted but discarded.
- Website and network target details are partially unmapped into the generic
  `assets` table.
- The API has create and get-by-ID operations but no list, update, delete, or
  dashboard/risk-analysis endpoints.
- `setup_db.py` uses interpolated database-name SQL when creating the database;
  this should be replaced with safe identifier handling if the name becomes
  externally configurable.
- The active database connection configuration comes from `.env`; credentials
  must remain untracked.
- The spec's previously flagged global import-time connection issue is not
  present in the current `backend/database.py`; the pool is explicitly lazy.
- The current inspected repository does not establish a confirmed hardcoded
  asset ID in the active ZAP ingestion path or a confirmed inverted severity
  mapping. Those claims require a separate ingestion-behavior audit.

## Recommendation

Adapting the spec's UI and routes onto the existing five-table schema requires
less immediate rework. The current assessment form already maps naturally to
generic `assets` rows, and the working API/database path can be extended with
read endpoints and risk calculations.

A full migration toward the spec's twelve-table model would require:

1. Adding `users` and `assessments`, including authentication and tenant
   ownership.
2. Adding the four target/integration tables and deciding whether they own or
   reference generic assets.
3. Adding `assessment_id` foreign keys to assets, findings, risk results,
   recommendations, and scenario data.
4. Renaming or replacing `risk_scores` and
   `investment_recommendations`.
5. Adding compliance, scenario, and dashboard query models.
6. Backfilling existing rows into a default assessment and defining ownership.
7. Replacing direct `psycopg2` repository code with Prisma migrations/client
   code if Prisma remains a requirement.

The practical path is therefore to retain PostgreSQL and the existing five-table
foundation, add assessment/user boundaries incrementally, and implement the
missing read/risk/dashboard APIs before introducing the full twelve-table
specification.

