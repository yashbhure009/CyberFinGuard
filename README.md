# 🛡️ CyberFinGuard

## 📌 Problem Statement (SIH26105)
**AI-Powered Continuous Cyber Risk Quantification and Investment Optimization Platform**

CyberFinGuard ek AI-powered platform hai jo technical cybersecurity telemetry ko business asset criticality aur control effectiveness ke saath correlate karta hai. Yeh cyber risk ko **continuous, monetary terms (₹)** mein quantify karta hai, likelihood aur financial impact estimate karta hai, aur **budget constraints** ke andar cost-effective mitigation strategies recommend karta hai.

---

## 🎯 What This Platform Does

| Feature | Description |
| :--- | :--- |
| **Risk Quantification** | Vulnerabilities, misconfigurations, alerts ko **₹ (Rupee) values** mein convert karta hai |
| **Investment Optimization** | Security budget kahan lagayein, maximum **ROI** ke saath recommend karta hai |
| **Continuous Monitoring** | Wazuh, OpenVAS, Prowler, Keycloak, OWASP ZAP se real-time data ingest karta hai |
| **AI Decision Support** | Predictive analytics, NLP chatbot, aur what-if scenario simulation |
| **Compliance Mapping** | ISO 27001, NIST CSF, CIS Controls, RBI CSF, SEBI CSCRF se mapping |

---

## 🏗️ Architecture
┌─────────────────────────────────────────────────────────────────────┐
│ DATA SOURCES │
│ ZAP │ Nmap │ Nuclei │ Wazuh │ Prowler │ Keycloak │ NVD │ EPSS │ KEV │
└─────────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────┐
│ INGESTION & PROCESSING LAYER │
│ Clean → Validate → Enrich → Map → PostgreSQL │
└─────────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────┐
│ RISK QUANTIFICATION ENGINE │
│ SLE = Asset_Value × (CVSS/10) │
│ ARO = Base_Likelihood × Threat_Multiplier × Control_Multiplier │
│ ALE = SLE × ARO │
│ Monte Carlo (100,000 iterations) → VaR, CVaR │
└─────────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────┐
│ AI DECISION SUPPORT LAYER │
│ ML Model + NLP Chatbot + What-If Simulator │
└─────────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────┐
│ INVESTMENT OPTIMIZATION │
│ Knapsack Solver → ROI → Recommendations │
└─────────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────┐
│ DASHBOARDS (CISO / CFO / Technical) │
│ Executive View │ Technical View │ Compliance View │
└─────────────────────────────────────────────────────────────────────┘

text

---

## 🛠️ Tech Stack

| Layer | Tools |
| :--- | :--- |
| **Data Ingestion** | Python, requests, subprocess |
| **Security Tools** | ZAP, Nmap, Nuclei, Wazuh, Prowler, Keycloak |
| **Threat Intel** | NVD, EPSS, CISA KEV |
| **Database** | PostgreSQL 15 (Docker) |
| **Risk Engine** | Python (SLE/ARO/ALE + Monte Carlo) |
| **AI/ML** | Scikit-learn, NLP |
| **Optimization** | Knapsack (scipy.optimize) |
| **Backend** | FastAPI |
| **Frontend** | React / Next.js |

---

## 🚀 Quick Start

### 1️⃣ Clone

```bash
git clone https://github.com/yashbhure009/CyberFinGuard.git
cd CyberFinGuard
2️⃣ Configure .env
bash
cp .env.example .env
.env mein apne values daalo:

env
DB_HOST=localhost
DB_NAME=cyber_risk_db
DB_USER=postgres
DB_PASSWORD=your_password
DB_PORT=5432

NMAP_PATH=C:\Program Files (x86)\Nmap\nmap.exe
NUCLEI_PATH=D:\Tools\Nuclei\nuclei.exe

WAZUH_API_URL=https://<wazuh-ip>:55000
WAZUH_USERNAME=admin
WAZUH_PASSWORD=your_password

KALI_HOST=<kali-ip>
KALI_SSH_PASSWORD=your_password

KEYCLOAK_URL=http://<kali-ip>:8080
KEYCLOAK_REALM=cyberfinguard
3️⃣ Install
bash
pip install -r requirements.txt
4️⃣ Start PostgreSQL
bash
docker run -d --name postgres-risk \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=cyber_risk_db \
  -p 5432:5432 \
  postgres:15
5️⃣ Setup Database
bash
python setup_db.py
6️⃣ Run Ingestion
bash
python main.py
Output: data/unified_findings/latest.json

📁 Project Structure
text
CyberFinGuard/
├── backend/
│   ├── ingestion/           # 6 ingestors
│   ├── enrichment/          # Threat intel + analyzer
│   ├── database.py
│   ├── unified_schema.py
│   └── api.py               # FastAPI
├── data/
│   ├── unified_findings/    # Output JSON
│   └── analytics/           # Graphs
├── frontend/                # React dashboard
├── risk_engine/             # SLE/ARO/ALE calculator
├── main.py
├── setup_db.py
├── requirements.txt
└── README.md
🔥 Key Innovations
Real tools integration — ZAP, Nmap, Nuclei (real scans)

9 data sources — SIEM, EDR, IAM, CSPM, vuln, threat intel

CISA KEV + EPSS — Real-time threat intelligence

Monte Carlo — 100,000 iterations for VaR/CVaR

Distributed architecture — Multi-laptop setup

Interactive what-if — Scenario simulation

AI chatbot — Natural language queries

5 compliance frameworks — ISO, NIST, CIS, RBI, SEBI
