
# CyberFinGuard

## AI-powered continuous cyber-risk quantification

CyberFinGuard connects technical security findings with business impact and presents risk for security, technology, compliance, and executive teams.

Use this project only against systems and cloud accounts for which you have explicit authorization.

## What the project does

1. Accepts an authorized HTTP or HTTPS website target.
2. Saves the target as an asset in PostgreSQL.
3. Starts a background website scan.
4. Runs OWASP ZAP and Nuclei.
5. Normalizes findings into PostgreSQL and data/unified_findings/latest.json.
6. Enriches vulnerability information using CISA KEV, EPSS, and NVD.
7. Collects business impact such as value, criticality, downtime, recovery, data sensitivity, and regulations.
8. Collects MFA, WAF, and EDR control status.
9. Displays technical, risk-analysis, executive, and compliance views.
10. Produces recommendations and a PDF summary.

Optional integrations include Nmap, Wazuh, Prowler/AWS, and Keycloak.

## Architecture

~~~text
Browser
  |
  v
Next.js frontend :3000
  |
  | /api proxy
  v
Flask API :8000
  |
  +--> PostgreSQL :5432
  +--> main.py background scan
          +--> OWASP ZAP :8080
          +--> Nuclei executable
          +--> PostgreSQL findings
          +--> data/unified_findings/latest.json
~~~

## Technology

| Layer | Implementation |
| --- | --- |
| Frontend | Next.js, React, TypeScript |
| Backend | Flask in backend/live_api.py |
| Database | PostgreSQL |
| Website scanning | OWASP ZAP and Nuclei |
| Network discovery | Nmap, optional |
| SIEM/EDR | Wazuh, optional |
| Cloud security | Prowler and AWS, optional |
| IAM | Keycloak, optional |
| Threat intelligence | CISA KEV, EPSS, NVD |
| Ingestion | Python modules in backend/ingestion |
| Reports | Backend PDF generation |

## Services to start

### Required for the website assessment

| Order | Service | Address | Purpose |
| ---: | --- | --- | --- |
| 1 | PostgreSQL | localhost:5432 | Persistent application data |
| 2 | OWASP ZAP | localhost:8080 | Dynamic website scanning |
| 3 | Flask API | 127.0.0.1:8000 | Backend and scan control |
| 4 | Next.js | localhost:3000 | Browser interface |

Nuclei must also be installed locally, but it runs as a subprocess rather than a permanent service.

### Optional services

| Service | Purpose |
| --- | --- |
| Nmap | Network discovery |
| Wazuh manager/API/indexer | SIEM and endpoint telemetry |
| Keycloak | IAM users, roles, groups, and events |
| Prowler | AWS security posture management |
| AWS account | Cloud scan source |
| NVD, EPSS, CISA KEV | Vulnerability enrichment |
| Remote risk model | Hosted risk scoring |
| OpenRouter/provider | Optional assistant functionality |

Wazuh, Keycloak, Prowler, AWS, and Nmap are not required for the basic website workflow.

## Prerequisites

- Python 3.10 or newer.
- Node.js and npm compatible with frontend/package.json.
- PostgreSQL 15 or newer.
- Git.
- Docker Desktop if using containerized PostgreSQL.
- OWASP ZAP.
- Nuclei executable and templates.

Optional: Nmap, Wazuh, Keycloak, Prowler, AWS access, and a configured risk-model provider.

## Install on Windows

Run PowerShell from the repository root:

~~~powershell
cd D:\PROJECT\CyberFinGuard\CyberFinGuard
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt

cd frontend
npm install
cd ..
~~~

If the virtual environment already exists, skip its creation. If activation is blocked, use .\venv\Scripts\python.exe directly.

## PostgreSQL setup

### Docker

Run once:

~~~powershell
docker run -d --name postgres-risk -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=cyber_risk_db -p 5432:5432 postgres:15
~~~

Later sessions:

~~~powershell
docker start postgres-risk
docker ps
docker logs postgres-risk
~~~

### Existing PostgreSQL

Set the correct values in the root .env:

~~~dotenv
DB_HOST=localhost
DB_NAME=cyber_risk_db
DB_USER=postgres
DB_PASSWORD=your-postgres-password
DB_PORT=5432
~~~

Initialize the schema:

~~~powershell
.\venv\Scripts\python.exe setup_db.py
~~~

For demo data only:

~~~powershell
.\venv\Scripts\python.exe setup_db.py --sample
~~~

Do not use --sample for a clean live assessment database.

## Environment configuration

Create the root environment file:

~~~powershell
Copy-Item .env.example .env
~~~

Never commit .env. It may contain database passwords, scanner credentials, cloud keys, certificates, or AI-provider keys.

### Database

~~~dotenv
DB_HOST=localhost
DB_NAME=cyber_risk_db
DB_USER=postgres
DB_PASSWORD=your-password
DB_PORT=5432
~~~

### OWASP ZAP

~~~dotenv
ZAP_API_URL=http://localhost:8080
ZAP_API_KEY=
ZAP_TARGET_URL=https://httpbin.org
~~~

Start ZAP before scanning and configure its API on localhost port 8080. Set ZAP_API_KEY if API-key protection is enabled.

Optional proxy settings:

~~~dotenv
SCANNER_HTTP_PROXY=http://127.0.0.1:8080
RISK_MODEL_PROXY=http://127.0.0.1:8080
ZAP_PROXY_CA_CERT=data\zap_proxy_root.cer
~~~

Only use SCANNER_HTTP_PROXY when ZAP accepts proxy traffic.

### Nuclei

~~~dotenv
NUCLEI_PATH=D:\Tools\Nuclei\nuclei.exe
NUCLEI_TARGET_URL=https://httpbin.org
NUCLEI_RATE_LIMIT=40
NUCLEI_CONCURRENCY=15
NUCLEI_REQUEST_TIMEOUT=8
NUCLEI_SCAN_TIMEOUT=600
NUCLEI_MAX_HOST_ERROR=10
~~~

Set NUCLEI_PATH to the real executable. Reduce rate and concurrency for fragile targets.

### Nmap

~~~dotenv
NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe
~~~

### Wazuh

~~~dotenv
WAZUH_API_URL=https://localhost:55000
WAZUH_USERNAME=wazuh-wui
WAZUH_PASSWORD=your-wazuh-password
WAZUH_INDEXER_URL=https://localhost:9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASSWORD=your-indexer-password
WAZUH_MANAGER_IP=localhost
~~~

### Keycloak

~~~dotenv
KEYCLOAK_URL=http://127.0.0.1:8090
KEYCLOAK_ADMIN=admin
KEYCLOAK_PASSWORD=your-keycloak-password
KEYCLOAK_REALM=master
~~~

### Prowler and AWS

~~~dotenv
PROWLER_PATH=C:\Users\your-username\.local\bin\prowler.exe
AWS_ACCESS_KEY_ID=your-access-key
AWS_SECRET_ACCESS_KEY=your-secret-key
AWS_DEFAULT_REGION=ap-south-1
~~~

Use least-privilege or short-lived AWS credentials.

### Threat intelligence

~~~dotenv
CISA_KEV_URL=https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
EPSS_API_URL=https://api.first.org/data/v1/epss
NVD_API_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
NVD_API_KEY=
~~~

### Runtime, output, and encoding

~~~dotenv
POLL_INTERVAL_SECONDS=300
INGESTION_BATCH_SIZE=100
UNIFIED_OUTPUT_DIR=data/unified_findings
ANALYTICS_OUTPUT_DIR=data/analytics
PYTHONUTF8=1
PYTHONIOENCODING=utf-8
~~~

### API and frontend networking

~~~dotenv
API_HOST=127.0.0.1
API_PORT=8000
FRONTEND_ORIGIN=http://localhost:3000,http://127.0.0.1:3000
~~~

frontend/next.config.ts proxies /api requests to port 8000. Normally no frontend API setting is needed locally. For a separate browser-accessible API, create frontend/.env.local:

~~~dotenv
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000
~~~

Restart Next.js after changing frontend environment variables or next.config.ts.

### Optional AI/provider configuration

~~~dotenv
OPENROUTER_API_KEY=your-key
OPENROUTER_BASE_URL=https://openrouter.ai/api/v1
OPENROUTER_MODEL=openai/gpt-4o-mini
OPENROUTER_APP_TITLE=CyberFinGuard
~~~

## Start the project

Use separate PowerShell windows.

### Window 1: PostgreSQL

~~~powershell
docker start postgres-risk
~~~

Skip this if PostgreSQL runs as a Windows service.

### Window 2: OWASP ZAP

Start ZAP Desktop or the ZAP daemon. Confirm the API is reachable at the configured ZAP_API_URL.

### Window 3: Flask API

~~~powershell
cd D:\PROJECT\CyberFinGuard\CyberFinGuard
.\venv\Scripts\python.exe -m backend.live_api
~~~

The API listens on http://127.0.0.1:8000.

Compatibility command:

~~~powershell
.\venv\Scripts\python.exe backend\api.py
~~~

Run only one API process.

Health check:

~~~powershell
Invoke-WebRequest http://127.0.0.1:8000/api/health
~~~

### Window 4: Next.js

~~~powershell
cd D:\PROJECT\CyberFinGuard\CyberFinGuard\frontend
npm run dev
~~~

Open http://localhost:3000/assessment.

## First assessment

1. Enter an authorized URL beginning with http:// or https://.
2. Click Save website and start scan.
3. Keep PostgreSQL, ZAP, the API, and the frontend running.
4. Ensure NUCLEI_PATH is valid.
5. Enter business impact values.
6. Wait for scan status to become complete.
7. Review scanner-derived inputs.
8. Enter MFA, WAF, and EDR status.
9. Submit the assessment.
10. Review the technical, executive, risk-analysis, and compliance pages.

Runtime files:

| File | Purpose |
| --- | --- |
| data/scan_config.json | Saved target and assessment configuration |
| data/scan_status.json | Current scan state |
| data/scan.log | Scanner output |
| data/unified_findings/latest.json | Latest normalized findings |

## API endpoints

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | /api/health | Health check |
| POST | /api/assets/website | Save website asset |
| GET | /api/assessment/config | Load assessment configuration |
| POST | /api/scan/run | Start website scan |
| GET | /api/scan/status | Read scan progress |
| POST | /api/assets/business-context | Save business impact |
| GET | /api/assessment/model-preview | Preview risk inputs |
| POST | /api/assessment/submit | Submit controls and start risk assessment |
| GET | /api/assessment/status/id | Read assessment status |
| GET | /api/dashboard/technical | Technical dashboard |
| GET | /api/dashboard/executive | Executive dashboard |
| GET | /api/risk-analysis | Risk-analysis workspace |
| GET | /api/compliance/summary | Compliance summary |
| GET | /api/compliance/findings | Compliance mappings |
| POST | /api/assistant/query | Assistant request |
| GET | /api/assessment/summary.pdf | PDF summary |

## Standalone scan

The API normally starts scans automatically. Direct execution is also possible:

~~~powershell
.\venv\Scripts\python.exe main.py https://httpbin.org/
~~~

Without a target argument, main.py uses the target in data/scan_config.json when available.

## Project structure

~~~text
CyberFinGuard/
├── backend/
│   ├── live_api.py                 # Current Flask API
│   ├── api.py                      # Compatibility launcher
│   ├── ingestion/                  # Scanner ingestors
│   ├── enrichment/                 # Threat intelligence
│   ├── assessment_pipeline.py      # Risk input transformation
│   ├── remote_risk_model.py        # Hosted risk integration
│   ├── risk_estimation.py          # Local risk estimation
│   └── pdf_report.py               # PDF generation
├── frontend/
│   ├── src/app/                    # Next.js pages
│   ├── src/components/             # UI components
│   ├── src/lib/api.ts              # API client
│   └── next.config.ts              # API proxy
├── data/                           # Runtime files and scan outputs
├── risk_engine/
├── main.py
├── setup_db.py
├── requirements.txt
├── .env.example
└── PROJECT_RUNBOOK.md
~~~

## Troubleshooting

### Frontend shows Request failed (404)

Start the canonical API and verify it:

~~~powershell
.\venv\Scripts\python.exe -m backend.live_api
Invoke-WebRequest http://127.0.0.1:8000/api/health
~~~

Restart npm run dev if next.config.ts changed. A target website returning HTTP 404 is different from the CyberFinGuard API returning 404.

### Backend is not reachable

Check that the API uses port 8000, the frontend uses port 3000, and the frontend proxy targets 127.0.0.1:8000.

### Database unavailable

~~~powershell
docker ps
docker logs postgres-risk
.\venv\Scripts\python.exe setup_db.py
~~~

Verify DB_HOST, DB_NAME, DB_USER, DB_PASSWORD, and DB_PORT.

### Scan fails or stays running

~~~powershell
Get-Content data\scan.log -Wait
Get-Content data\scan_status.json
~~~

Check ZAP, NUCLEI_PATH, target reachability, database availability, and scanner permissions. Reduce Nuclei load if needed:

~~~dotenv
NUCLEI_RATE_LIMIT=10
NUCLEI_CONCURRENCY=3
NUCLEI_REQUEST_TIMEOUT=15
~~~

### No findings

Zero findings can be valid. Confirm the scan completed and inspect data/scan.log for ingestion or database errors.

### Risk result stays pending

The risk model may be unavailable, may reject input, or may be missing required values. Check the assessment status endpoint and backend logs.

### Windows encoding errors

~~~dotenv
PYTHONUTF8=1
PYTHONIOENCODING=utf-8
~~~

Use the project virtual environment.

## Security rules

- Rotate credentials or keys exposed in a shared file, screenshot, terminal, or chat.
- Never commit .env, cloud credentials, scanner secrets, certificates, or sensitive logs.
- Keep the API bound to localhost unless authentication is configured.
- Do not expose PostgreSQL, ZAP, Wazuh, Keycloak, or Flask directly to the internet.
- Use least-privilege AWS and scanner accounts.
- Scan only authorized systems.
- Treat findings and logs as sensitive.
- Back up PostgreSQL before destructive changes.
- Do not use setup_db.py --sample for live data.

## Validation

~~~powershell
.\venv\Scripts\python.exe -m pip show Flask flask-cors psycopg2-binary python-dotenv requests pandas numpy matplotlib
Invoke-WebRequest http://127.0.0.1:8000/api/health
cd frontend
npm run build
Test-Path 'C:\Program Files (x86)\Nmap\nmap.exe'
Test-Path 'D:\Tools\Nuclei\nuclei.exe'
~~~

## First-run checklist

- [ ] Python environment and dependencies installed.
- [ ] Node dependencies installed.
- [ ] PostgreSQL running on port 5432.
- [ ] Root .env created with database values.
- [ ] setup_db.py completed successfully.
- [ ] ZAP running on port 8080.
- [ ] Nuclei executable path is correct.
- [ ] API health check succeeds.
- [ ] Frontend opens at localhost:3000/assessment.
- [ ] Authorized test URL entered.
- [ ] data/scan.log monitored during the first scan.

For additional operational detail, see PROJECT_RUNBOOK.md.

