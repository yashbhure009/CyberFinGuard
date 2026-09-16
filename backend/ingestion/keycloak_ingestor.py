"""
Keycloak Data Ingestor
Connects via SSH to Kali or Admin API directly and retrieves IAM posture data.
"""

import os
import sys
import json
import logging
import requests
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from database import db
except ImportError:
    from backend.database import db

try:
    from ingestion.common import configured, stable_id, insert_finding
except ModuleNotFoundError:
    from backend.ingestion.common import configured, stable_id, insert_finding

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class KeycloakConfig:
    def __init__(self):
        self.ssh_host = os.getenv("KALI_HOST", "")
        self.ssh_port = int(os.getenv("KALI_SSH_PORT", "22"))
        self.ssh_username = os.getenv("KALI_USERNAME", "kali")
        self.ssh_password = os.getenv("KALI_SSH_PASSWORD", "")
        self.keycloak_url = os.getenv("KEYCLOAK_URL", "http://127.0.0.1:8080")
        self.keycloak_admin = os.getenv("KEYCLOAK_ADMIN", "admin")
        self.keycloak_password = os.getenv("KEYCLOAK_PASSWORD", "")
        self.keycloak_realm = os.getenv("KEYCLOAK_REALM", "cyberfinguard")


class KeycloakIngestor:
    def __init__(self, config: KeycloakConfig = None):
        self.config = config or KeycloakConfig()
        self.ssh_client = None

    def connect_ssh(self):
        """Connect to Kali Linux using SSH if configured."""
        if not configured(self.config.ssh_host) or not configured(self.config.ssh_password):
            logger.info("SSH configuration missing for Keycloak. Will attempt direct HTTP API if configured.")
            return False
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                self.config.ssh_host,
                port=self.config.ssh_port,
                username=self.config.ssh_username,
                password=self.config.ssh_password,
                timeout=15
            )
            self.ssh_client = client
            logger.info("Connected to Kali via SSH for Keycloak.")
            return True
        except Exception as e:
            logger.warning(f"Keycloak SSH connection failed: {e}")
            return False

    def close(self):
        """Close SSH connection."""
        if self.ssh_client:
            try:
                self.ssh_client.close()
            except Exception:
                pass
            self.ssh_client = None
            logger.info("SSH connection closed.")

    def _direct_token(self):
        """Fetch admin token via direct API."""
        if not configured(self.config.keycloak_url) or not configured(self.config.keycloak_password):
            raise RuntimeError("KEYCLOAK_URL and KEYCLOAK_PASSWORD are required.")
        token_url = f"{self.config.keycloak_url.rstrip('/')}/realms/master/protocol/openid-connect/token"
        resp = requests.post(
            token_url,
            data={
                "username": self.config.keycloak_admin,
                "password": self.config.keycloak_password,
                "grant_type": "password",
                "client_id": "admin-cli",
            },
            timeout=10,
            verify=os.getenv("KEYCLOAK_VERIFY_TLS", "true").lower() == "true"
        )
        if not resp.ok:
            raise RuntimeError(f"Keycloak token request failed ({resp.status_code}): {resp.text}")
        data = resp.json()
        token = data.get("access_token")
        if not token:
            raise RuntimeError("Keycloak did not return an access_token.")
        return token

    def collect(self):
        """Collect Keycloak users and IAM posture."""
        try:
            token = self._direct_token()
            users_url = f"{self.config.keycloak_url.rstrip('/')}/admin/realms/{self.config.keycloak_realm}/users?max=1000"
            headers = {"Authorization": f"Bearer {token}"}
            resp = requests.get(users_url, headers=headers, timeout=15)
            if resp.ok:
                users = resp.json()
                return {"users": users, "realm": self.config.keycloak_realm}
        except Exception as e:
            logger.warning(f"Direct Keycloak API collection failed ({e}). Returning fallback/configured state.")
        
        return {"users": [], "realm": self.config.keycloak_realm, "status": "configured" if configured(self.config.keycloak_url) else "not_configured"}

    def run(self):
        """Full Keycloak run workflow."""
        try:
            if not self.ssh_client:
                self.connect_ssh()
            data = self.collect()
            users = data.get("users", [])
            totp_count = sum(1 for u in users if u.get("totp"))
            mfa_rate = (totp_count / len(users) * 100) if users else 0.0
            
            asset_id = stable_id("keycloak", self.config.keycloak_realm)
            finding_id = stable_id("keycloak", asset_id, "mfa_rate")
            
            severity = "critical" if mfa_rate < 30 else ("high" if mfa_rate < 70 else "medium")
            desc = f"MFA adoption is {mfa_rate:.0f}%. {totp_count} of {len(users)} Keycloak users have TOTP configured."
            
            finding = {
                "finding_id": finding_id,
                "asset_id": asset_id,
                "asset_name": f"Keycloak {self.config.keycloak_realm}",
                "asset_type": "iam",
                "source": "keycloak",
                "title": f"Keycloak IAM - MFA Adoption ({mfa_rate:.0f}%)",
                "description": desc,
                "severity": severity,
                "raw_data": {"users_count": len(users), "totp_count": totp_count, "mfa_rate": mfa_rate}
            }
            insert_finding(finding)
            self.close()
            return {"source": "keycloak", "users": len(users), "mfa_rate": mfa_rate, "status": "success"}
        except Exception as e:
            logger.error(f"Keycloak ingestion failed: {e}")
            self.close()
            return {"source": "keycloak", "status": "failed", "error": str(e)}


if __name__ == "__main__":
    ingestor = KeycloakIngestor()
    print(ingestor.run())
