# CyberFinGuard – Data Ingestion

The ingestion layer collects security and IAM data from external tools, normalizes it, and stores it in PostgreSQL for risk analysis.

## Integrated Sources

### Prowler

Prowler is used to assess AWS security and configuration.

- Runs on Kali Linux
- Scans AWS security configurations
- Collects security findings
- Normalizes findings
- Stores findings and assets in PostgreSQL

### Keycloak

Keycloak provides IAM and authentication information.

- Users
- Roles
- Groups
- MFA status
- Account status
- Authentication events

Keycloak data is normalized and stored in PostgreSQL.

---

## Setup

Kali Linux is currently used as the security-tool environment for Prowler and Keycloak.

Configure SSH access from the CyberFinGuard backend to Kali.

Create a `.env` file with the required configuration:

```env
KALI_HOST=<kali-ip>
KALI_SSH_PORT=22
KALI_USERNAME=<kali-username>
KALI_PASSWORD=<kali-password>

KEYCLOAK_URL=http://127.0.0.1:8080
KEYCLOAK_ADMIN=<keycloak-admin>
KEYCLOAK_PASSWORD=<keycloak-password>
KEYCLOAK_REALM=cyberfinguard
Prowler Execution
1. Activate Prowler on Kali
cd /home/kali/prowler
source .venv/bin/activate
2. Verify AWS credentials
aws sts get-caller-identity
3. Run Prowler
prowler aws

Prowler generates the security scan results on Kali.

4. Run the CyberFinGuard Prowler ingestion

From the CyberFinGuard project directory on Windows:

python backend/ingestion/prowler_ingestor.py

The ingestor connects to Kali through SSH, retrieves the Prowler results, normalizes them, and loads them into PostgreSQL.

Keycloak Execution
1. Start Keycloak on Kali
sudo docker start keycloak

Verify that it is running:

sudo docker ps

Keycloak runs on:

http://127.0.0.1:8080
2. Verify Keycloak

Open the Keycloak Admin Console and make sure the cyberfinguard realm and required users, roles, groups, and MFA configuration are available.

3. Run the Keycloak ingestion

From the CyberFinGuard project directory on Windows:

python backend/ingestion/keycloak_ingestor.py

The ingestor connects to Kali through SSH, retrieves Keycloak IAM data, and collects authentication events.

4. Load Keycloak data into PostgreSQL
python backend/ingestion/keycloak_db_loader.py

This stores the collected IAM data in PostgreSQL.

Database Tables
Prowler
assets
findings
Keycloak
iam_users
iam_roles
iam_groups
iam_user_roles
iam_user_groups
iam_authentication_events
Data Flow
Security Tools
      ↓
   Ingestion
      ↓
 Normalization
      ↓
  PostgreSQL
      ↓
Risk Engine / AI Layer

### Wazuh

Wazuh is used to collect endpoint and security telemetry.

- Runs using WSL and Docker Desktop
- Monitors registered endpoints through Wazuh agents
- Collects security alerts
- Extracts MITRE ATT&CK techniques
- Normalizes alerts into CyberFinGuard findings
- Stores alerts and endpoint assets in PostgreSQL

Wazuh is currently deployed using the Wazuh Docker single-node setup.

### Wazuh Setup

1. Start Docker Desktop

Make sure Docker Desktop is running and WSL integration is enabled.

2. Verify Wazuh containers

From WSL:

```bash
docker ps

The following Wazuh containers should be running:

Wazuh Manager
Wazuh Indexer
Wazuh Dashboard
Verify Wazuh API
curl -k https://localhost:55000

The API should respond and require authentication.

Configure Wazuh environment variables

Add the following to the CyberFinGuard .env file:

WAZUH_API_URL=https://localhost:55000
WAZUH_USERNAME=<wazuh-api-username>
WAZUH_PASSWORD=<wazuh-api-password>

WAZUH_INDEXER_URL=https://localhost:9200
WAZUH_INDEXER_USER=<indexer-username>
WAZUH_INDEXER_PASSWORD=<indexer-password>

Do not commit the .env file or any credentials to GitHub.

Wazuh Execution

From the CyberFinGuard project directory on Windows:

python -u backend\ingestion\wazuh_ingestor.py

The Wazuh ingestor:

Authenticates with the Wazuh API.
Retrieves registered Wazuh agents.
Synchronizes agents as assets in PostgreSQL.
Retrieves Wazuh security alerts from the Indexer.
Extracts severity and MITRE ATT&CK techniques.
Normalizes alerts into CyberFinGuard findings.
Stores the findings in PostgreSQL.

Example output:

Database connected
agents HTTP status: 200
agents count: 2
MITRE techniques found: XX
Done: X new assets, XX alerts
Database Tables

Wazuh uses the existing CyberFinGuard tables:

assets
findings

Wazuh agents are stored as assets, while Wazuh alerts are stored as security findings.

Wazuh Role in CyberFinGuard

Wazuh provides endpoint and security telemetry and complements the other ingestion sources:

Source	Purpose
Prowler	AWS/cloud security
Keycloak	IAM, users, roles, groups and MFA
Wazuh	Endpoint and security telemetry
ZAP	Web application security
OpenVAS	Vulnerability scanning

The collected data is stored in PostgreSQL and can subsequently be used by the CyberFinGuard risk engine for risk analysis and quantification.


Then replace your existing **Current Status** with:

```markdown
## Data Flow

```text
Security Tools
      ↓
   Ingestion
      ↓
 Normalization
      ↓
  PostgreSQL
      ↓
Risk Engine / AI Layer
Current Status

Prowler – Integrated
Keycloak – Integrated
Wazuh – Integrated
OpenVAS – To be integrated
ZAP – Integrated
