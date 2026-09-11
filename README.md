## 🚀 **GitHub Push Karo — README Update Ke Saath**

Chal step-by-step karte hain. Pehle README update, phir push.

---

## 📝 **Step 1: README.md Update Karo**

**File:** `D:\PROJECT\CyberFinGuard\CyberFinGuard\README.md`

VS Code mein kholo aur ye **complete content** paste karo:

```markdown
# 🛡️ CyberFinGuard - AI-Powered Cyber Risk Quantification Platform

## 📌 Problem Statement (SIH26105)
**AI-Powered Continuous Cyber Risk Quantification and Investment Optimization Platform**

A platform that answers one critical question for leadership:
> *"How many rupees are we at risk of losing to a cyberattack right now, and what's the smartest way to spend our security budget to reduce that number?"*

---

## 🎯 What This Platform Does

| Feature | Description |
| :--- | :--- |
| **Risk Quantification** | Converts vulnerabilities, misconfigurations, and alerts into **₹ (Rupee) values** |
| **Investment Optimization** | Recommends where to spend security budget for maximum **ROI** |
| **Continuous Monitoring** | Ingests data from **Wazuh, OpenVAS, Prowler, Keycloak, OWASP ZAP** in real-time |
| **Executive Dashboard** | Board-ready visualizations showing risk exposure and mitigation plans |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DATA SOURCES                                     │
│  Wazuh │ OpenVAS │ Prowler │ Keycloak │ OWASP ZAP │ CISA KEV │ EPSS │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    DATA INGESTION LAYER                            │
│  Pollers → Normalize → Store in PostgreSQL                        │
└─────────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                    RISK SCORING ENGINE                             │
│  SLE = Asset_Value × (CVSS/10)                                    │
│  ARO = Base_Likelihood × Threat_Multiplier × Control_Multiplier   │
│  ALE = SLE × ARO                                                  │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ✅ Current Status

| Component | Status |
| :--- | :--- |
| ✅ Database Setup | PostgreSQL via Docker |
| ✅ ZAP Ingestor | **Working — Live scan of httpbin.org (53 findings)** |
| ✅ Spider Scan | Auto-crawl working |
| ✅ Data Normalization | Real alerts → unified schema |
| ⏳ OpenVAS Ingestor | Kali VM (pending) |
| ⏳ Keycloak Ingestor | Docker (pending) |
| ⏳ Risk Engine | Next phase |

---

## 📁 Project Structure

```
CyberFinGuard/
│
├── backend/
│   ├── __init__.py
│   ├── database.py
│   ├── ingestion/
│   │   ├── __init__.py
│   │   ├── wazuh_ingestor.py
│   │   ├── zap_ingestor.py         ← Working!
│   │   ├── openvas_ingestor.py
│   │   └── keycloak_ingestor.py
│   └── enrichment/
│       ├── __init__.py
│       └── threat_intel.py
│
├── ai_layer/
├── frontend/
├── risk_engine/
│
├── .env.example
├── .gitignore
├── docker-compose.yml
├── main.py
├── README.md
├── requirements.txt
└── setup_db.py
```

---

## 🚀 Quick Start (5 Minutes Setup)

### 1️⃣ Clone the Repository

```bash
git clone https://github.com/yashbhure009/CyberFinGuard.git
cd CyberFinGuard
```

### 2️⃣ Configure Environment Variables

```bash
cp .env.example .env
```

Edit `.env` with your actual values:

```env
# Database
DB_HOST=localhost
DB_NAME=cyber_risk_db
DB_USER=postgres
DB_PASSWORD=postgres
DB_PORT=5432

# OWASP ZAP
ZAP_API_URL=http://localhost:8080
ZAP_API_KEY=
ZAP_TARGET_URL=https://httpbin.org

# OpenVAS (Kali VM)
OPENVAS_HOST=<your-kali-ip>
OPENVAS_PORT=9390
OPENVAS_USERNAME=admin
OPENVAS_PASSWORD=admin

# Keycloak
KEYCLOAK_URL=http://localhost:8080
KEYCLOAK_ADMIN=admin
KEYCLOAK_PASSWORD=admin
```

> ⚠️ **NEVER commit `.env` to GitHub** — it contains secrets!

### 3️⃣ Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 4️⃣ Start PostgreSQL with Docker

```bash
docker run -d --name postgres-risk -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=cyber_risk_db -p 5432:5432 postgres:15
```

### 5️⃣ Setup Database

```bash
python setup_db.py
```

### 6️⃣ Start ZAP in Daemon Mode

```bash
# Windows
cd "C:\Program Files\ZAP\Zed Attack Proxy"
zap.bat -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

Verify ZAP is running:
```bash
curl.exe http://localhost:8080/JSON/core/view/version/
# Expected: {"version":"2.17.0"}
```

### 7️⃣ Run Data Ingestion

```bash
python main.py
```

---

## 📊 Example Output — Real ZAP Scan

```
============================================================
🚀 CyberFinGuard - Data Ingestion Pipeline
============================================================

INFO - 🕷️ Starting ZAP ingestion...
INFO - 🚀 Starting ZAP scan on https://httpbin.org
INFO - 🕷️ Spider scan ID: 0
INFO - 🕷️ Spider progress: 100%
INFO - ✅ Spider scan complete
INFO - 📊 Fetching alerts...
INFO - 📊 Found 53 alerts
INFO - ✅ Ingested: Content Security Policy (CSP) Header Not Set
INFO - ✅ Ingested: Missing Anti-clickjacking Header
INFO - ✅ Ingested: X-Content-Type-Options Header Missing
... (50 more)

============================================================
📊 INGESTION SUMMARY
🔹 ZAP:
   source: zap
   findings_ingested: 53
   target: https://httpbin.org
============================================================
```

---

## 🔧 Environment Setup for Teams

| Tool | Windows (Local) | Kali VM | Docker |
| :--- | :--- | :--- | :--- |
| **ZAP** | `http://localhost:8080` | `http://<kali-ip>:8080` | `http://localhost:8080` |
| **Wazuh** | — | `https://<kali-ip>:55000` | `https://localhost:55000` |
| **OpenVAS** | — | `https://<kali-ip>:9392` | `https://localhost:9392` |
| **Keycloak** | `http://localhost:8080` | `http://<kali-ip>:8080` | `http://localhost:8080` |

---

## 📊 Database Schema

| Table | Purpose |
| :--- | :--- |
| `assets` | Asset inventory (servers, databases, web apps) |
| `findings` | Security findings (vulnerabilities, alerts) |
| `asset_controls` | Security controls status (MFA, patching) |
| `risk_scores` | Calculated SLE, ARO, ALE per asset |
| `investment_recommendations` | Optimized budget allocation |

---

## 🛠️ Tech Stack

| Layer | Technologies |
| :--- | :--- |
| **Data Ingestion** | Python, requests, REST APIs |
| **Database** | PostgreSQL 15 (Docker) |
| **Security Tools** | OWASP ZAP, OpenVAS, Wazuh, Keycloak |
| **Threat Intel** | CISA KEV, EPSS, NVD |
| **Backend** | FastAPI (upcoming) |
| **Frontend** | React / Next.js (upcoming) |
| **ML** | Scikit-learn (upcoming) |

---

## 🆘 Troubleshooting

### Docker Error: "container already exists"

```bash
docker rm -f postgres-risk
docker run -d --name postgres-risk -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=cyber_risk_db -p 5432:5432 postgres:15
```

### Database Connection Error

```bash
docker ps | findstr postgres
docker restart postgres-risk
```

### ZAP Connection Error

Ensure ZAP is running in daemon mode:
```bash
zap.bat -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

### Module Not Found Error

```bash
pip install -r requirements.txt
```

### Foreign Key Constraint Error

Make sure asset exists before inserting findings:
```bash
python -c "import psycopg2; conn = psycopg2.connect(host='localhost', database='cyber_risk_db', user='postgres', password='postgres', port='5432'); cursor = conn.cursor(); cursor.execute(\"INSERT INTO assets (asset_id, asset_name, asset_type, environment, criticality, asset_value) VALUES ('httpbin_target', 'HTTPBin Test Target', 'web_app', 'testing', 2, 5000000) ON CONFLICT (asset_id) DO NOTHING\"); conn.commit(); cursor.close(); conn.close(); print('✅ Asset inserted!')"
```

---

## 🤝 Team

| Role | Name |
| :--- | :--- |
| Data Ingestion | Kartik / Yash Bhure |
| Risk Engine | Yash Bhure |
| AI/ML | Yash Adhav |
| Compliance | Yash More |
| Dashboard | Tanishka |
| Integration | Akansha |

---

## 📞 Contact

- **Repository:** https://github.com/yashbhure009/CyberFinGuard
- **Issue Tracker:** https://github.com/yashbhure009/CyberFinGuard/issues

---

**Made with ❤️ for SIH 2026 - Problem Statement SIH26105**
```

---

## 🚀 **Step 2: Git Push Karo**

```powershell
cd D:\PROJECT\CyberFinGuard\CyberFinGuard

# 1. Status check karo
git status

# 2. Sab files add karo
git add .

# 3. Commit karo
git commit -m "Updated README with real ZAP scan status, setup guide, and troubleshooting"

# 4. Push karo
git push origin main
```

---

## ⚠️ **Step 3: `.env` Verify Karo — GitHub Pe Nahi Jaana Chahiye**

```powershell
# .gitignore check karo
type .gitignore | findstr ".env"
```

**Expected:**
```
.env
!.env.example
```

**Agar `.env` tracked hai toh:**
```powershell
git rm --cached .env
git commit -m "Removed .env from tracking"
```

---

## 📋 **Step 4: Verify Karo GitHub Pe**

Push ke baad ye URL kholo:
**https://github.com/yashbhure009/CyberFinGuard**

Check karo:
- ✅ README updated hai (real ZAP scan status)
- ✅ `.env` **NOT visible** (ignore ho gaya)
- ✅ `.env.example` **visible** hai
- ✅ `backend/ingestion/zap_ingestor.py` updated hai

---

## 🎯 **Expected Git Output**

```
$ git status
On branch main
Changes not staged for commit:
    modified:   README.md
    modified:   backend/ingestion/zap_ingestor.py
    modified:   .gitignore

$ git add .
$ git commit -m "Updated README with real ZAP scan status"
[main abc1234] Updated README with real ZAP scan status
 3 files changed, 250 insertions(+), 20 deletions(-)

$ git push origin main
Enumerating objects: 12, done.
...
To https://github.com/yashbhure009/CyberFinGuard
   xxxxxxx..yyyyyyy  main -> main
```

---

## 🚀 **Ab Yeh Karo**

```powershell
cd D:\PROJECT\CyberFinGuard\CyberFinGuard

# README update karo (VS Code mein)
code README.md
# (Upar wala content paste karo, save karo)

# Push karo
git add .
git commit -m "Updated README with real ZAP scan status and setup guide"
git push origin main
```

---

**Output paste karo — main verify karunga!** 🚀
