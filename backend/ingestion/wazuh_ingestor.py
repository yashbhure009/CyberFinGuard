"""
Wazuh SIEM/EDR Ingestor
Collects security alerts from Wazuh REST API / Indexer and persists findings.
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


class WazuhConfig:
    def __init__(self):
        self.api_url = os.getenv("WAZUH_API_URL", "")
        self.username = os.getenv("WAZUH_USERNAME", "admin")
        self.password = os.getenv("WAZUH_PASSWORD", "")
        self.indexer_url = os.getenv("WAZUH_INDEXER_URL", "")
        self.indexer_user = os.getenv("WAZUH_INDEXER_USER", "admin")
        self.indexer_password = os.getenv("WAZUH_INDEXER_PASSWORD", "")
        self.verify_tls = os.getenv("WAZUH_VERIFY_TLS", "true").lower() == "true"


class WazuhIngestor:
    def __init__(self, config: WazuhConfig = None):
        self.config = config or WazuhConfig()

    def get_auth_token(self):
        """Authenticate with Wazuh API and return JWT token."""
        if not configured(self.config.api_url) or not configured(self.config.password):
            return None
        auth_url = f"{self.config.api_url.rstrip('/')}/security/user/authenticate"
        try:
            resp = requests.post(
                auth_url,
                auth=(self.config.username, self.config.password),
                verify=self.config.verify_tls,
                timeout=10
            )
            if resp.ok:
                return resp.json().get("data", {}).get("token")
        except Exception as e:
            logger.warning(f"Wazuh authentication failed: {e}")
        return None

    def fetch_alerts(self, token: str):
        """Fetch alerts from Wazuh API."""
        alerts_url = f"{self.config.api_url.rstrip('/')}/alerts?limit=100"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            resp = requests.get(alerts_url, headers=headers, verify=self.config.verify_tls, timeout=15)
            if resp.ok:
                return resp.json().get("data", {}).get("affected_items", [])
        except Exception as e:
            logger.warning(f"Failed to fetch Wazuh alerts: {e}")
        return []

    def run(self):
        """Run Wazuh ingestion pipeline."""
        if not configured(self.config.api_url):
            logger.info("Wazuh API not configured. Skipping Wazuh ingestion.")
            return {"source": "wazuh", "status": "not_configured", "findings_ingested": 0}

        token = self.get_auth_token()
        if not token:
            return {"source": "wazuh", "status": "auth_failed", "findings_ingested": 0}

        alerts = self.fetch_alerts(token)
        count = 0
        for alert in alerts:
            try:
                rule = alert.get("rule", {})
                agent = alert.get("agent", {})
                rule_id = rule.get("id", "wazuh_rule")
                agent_id = agent.get("id", "wazuh_agent")
                
                asset_id = stable_id("wazuh", agent_id)
                finding_id = stable_id("wazuh", asset_id, rule_id, alert.get("id", ""))
                
                level = rule.get("level", 0)
                severity = "critical" if level >= 12 else ("high" if level >= 8 else ("medium" if level >= 4 else "info"))
                
                finding = {
                    "finding_id": finding_id,
                    "asset_id": asset_id,
                    "asset_name": agent.get("name", f"Wazuh Agent {agent_id}"),
                    "asset_type": "endpoint",
                    "ip_address": agent.get("ip"),
                    "source": "wazuh",
                    "title": rule.get("description", f"Wazuh Rule {rule_id}"),
                    "description": f"Wazuh alert level {level} detected on agent {agent.get('name')}.",
                    "severity": severity,
                    "raw_data": alert
                }
                if insert_finding(finding):
                    count += 1
            except Exception as e:
                logger.error(f"Failed to normalize Wazuh alert: {e}")

        return {"source": "wazuh", "status": "success", "findings_ingested": count}


if __name__ == "__main__":
    ingestor = WazuhIngestor()
    print(ingestor.run())
