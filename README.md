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
| **Continuous Monitoring** | Ingests data from **Wazuh, OpenVAS, Prowler, Keycloak** in real-time |
| **Executive Dashboard** | Board-ready visualizations showing risk exposure and mitigation plans |

---

## 🏗️ Architecture
┌─────────────────────────────────────────────────────────────────────┐
│ DATA SOURCES │
│ Wazuh │ OpenVAS │ Prowler │ Keycloak │ CISA KEV │ EPSS │
└─────────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────┐
│ DATA INGESTION LAYER │
│ Pollers → Normalize → Store in PostgreSQL │
└─────────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────┐
│ RISK SCORING ENGINE │
│ SLE = Asset_Value × (CVSS/10) │
│ ARO = Base_Likelihood × Threat_Multiplier × Control_Multiplier │
│ ALE = SLE × ARO │
└─────────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────┐
│ AI & OPTIMIZATION LAYER │
│ ML Model (Likelihood Prediction) + Knapsack Optimizer │
└─────────────────────────────────────────────────────────────────────┘
│
▼
┌─────────────────────────────────────────────────────────────────────┐
│ DASHBOARD (React/Next.js) │
│ Executive View │ Technical View │ Investment Optimizer │
└─────────────────────────────────────────────────────────────────────┘


---

## 🚀 Quick Start (5 Minutes Setup)

### Clone the Repository

git clone https://github.com/yashbhure009/CyberFinGuard.git
cd CyberFinGuard

### Install Python Dependencies

pip install -r requirements.txt
### Start PostgreSQL with Docker

docker run -d --name postgres-risk \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=cyber_risk_db \
  -p 5432:5432 \
  postgres:15
### Setup Database

python setup_db.py
### Run Data Ingestion

python main.py
### Verify Database

python -c "from backend.database import db; print(db.execute_query('SELECT COUNT(*) FROM assets'))"



# Wazuh Configuration
WAZUH_API_URL=https://172.26.209.186:55000
WAZUH_USERNAME=admin
WAZUH_PASSWORD=SecretPassword
