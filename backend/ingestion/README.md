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
Current Status
Prowler – Integrated
Keycloak – Integrated
OpenVAS – To be integrated
Wazuh – To be integrated
ZAP – To be integrated
