"""
OWASP ZAP Ingestor — Nexora Website
Multi-account authenticated scanning
"""

import requests
import json
import logging
import uuid
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================
# Nexora Test Accounts
# ============================================================
NEXORA_ACCOUNTS = {
    "customer": {
        "email": "customer@nexora.local",
        "password": "NexoraCust2026!",
        "role": "Customer (Apex Global Financial)"
    },
    "employee": {
        "email": "employee@nexora.local",
        "password": "NexoraEmp2026!",
        "role": "Engineering Staff"
    },
    "finance": {
        "email": "finance@nexora.local",
        "password": "NexoraFin2026!",
        "role": "Corporate Finance"
    },
    "admin": {
        "email": "admin@nexora.local",
        "password": "NexoraAdmin2026!",
        "role": "Executive IT / Admin"
    },
    "secops": {
        "email": "secops@nexora.local",
        "password": "NexoraSec2026!",
        "role": "Cybersecurity SOC"
    }
}


class ZAPIngestor:
    def __init__(self):
        self.zap_url = os.getenv('ZAP_API_URL', 'http://localhost:8080')
        self.api_key = os.getenv('ZAP_API_KEY', '')
        self.session = requests.Session()

    def _call(self, endpoint, params=None):
        url = f"{self.zap_url}/JSON/{endpoint}/"
        if params is None:
            params = {}
        if self.api_key:
            params['apikey'] = self.api_key
        try:
            response = self.session.get(url, params=params, timeout=30)
            return response.json()
        except Exception as e:
            logger.error(f"ZAP API error: {e}")
            return None

    # ============================================================
    # AUTHENTICATION
    # ============================================================
    def setup_authenticated_context(self, target_url, account_name="admin"):
        """Setup ZAP context with login credentials"""
        account = NEXORA_ACCOUNTS.get(account_name)
        if not account:
            logger.warning(f"⚠️ Account {account_name} not found")
            return False

        logger.info(f"🔐 Setting up auth: {account['email']} ({account['role']})")

        # 1. Create context
        self._call("context/action/newContext", {"contextName": "nexora"})

        # 2. Include target in context
        self._call("context/action/includeInContext", {
            "contextName": "nexora",
            "regex": f"{target_url}.*"
        })

        # 3. Setup form-based authentication
        login_request = f"email={{{{%username%}}}}&password={{{{%password%}}}}".replace("{{", "%").replace("}}", "%")
        self._call("authentication/action/setAuthenticationMethod", {
            "contextId": "1",
            "authMethodName": "formBasedAuthentication",
            "authMethodConfigParams": f"loginUrl={target_url}login&loginRequestData=email%3D%7B%25username%25%7D%26password%3D%7B%25password%25%7D"
        })

        # 4. Create user
        self._call("users/action/newUser", {
            "contextId": "1",
            "name": account["email"]
        })

        # 5. Set credentials
        self._call("users/action/setAuthenticationCredentials", {
            "contextId": "1",
            "userId": "0",
            "authCredentialsConfigParams": f"username={account['email']}&password={account['password']}"
        })

        # 6. Enable user
        self._call("users/action/setUserEnabled", {
            "contextId": "1",
            "userId": "0",
            "enabled": "true"
        })

        logger.info(f"✅ Auth setup for {account['email']}")
        return True

    def verify_authentication(self):
        """Check if login worked"""
        result = self._call("users/view/authenticationCredentials", {
            "contextId": "1",
            "userId": "0"
        })
        if result:
            logger.info(f"✅ Auth verified: {result}")
            return True
        logger.warning("⚠️ Auth verification failed")
        return False

    # ============================================================
    # SPIDER — AJAX + Classic
    # ============================================================
    def start_ajax_spider(self, target_url):
        logger.info(f"🕷️ AJAX Spider: {target_url}")
        result = self._call("spiderAjax/action/scan", {
            "url": target_url,
            "maxChildren": 10,
            "recurse": True,
            "contextName": "nexora"
        })
        return result.get("scan") if result else None

    def wait_for_ajax_spider(self, scan_id, timeout=300):
        start = time.time()
        while time.time() - start < timeout:
            result = self._call("spiderAjax/view/status", {"scanId": scan_id})
            if result and "status" in result:
                status = int(result["status"])
                logger.info(f"🕷️ AJAX Spider: {status}%")
                if status >= 100:
                    return True
            time.sleep(5)
        return False

    # ============================================================
    # ACTIVE SCAN (Attacks)
    # ============================================================
    def start_active_scan(self, target_url):
        logger.info(f"🔥 Active Scan: {target_url}")
        result = self._call("ascan/action/scan", {
            "url": target_url,
            "recurse": True,
            "contextId": "1"
        })
        return result.get("scan") if result else None

    def wait_for_active_scan(self, scan_id, timeout=900):
        start = time.time()
        while time.time() - start < timeout:
            result = self._call("ascan/view/status", {"scanId": scan_id})
            if result and "status" in result:
                status = int(result["status"])
                logger.info(f"🔥 Active Scan: {status}%")
                if status >= 100:
                    return True
            time.sleep(10)
        return False

    # ============================================================
    # FETCH ALERTS
    # ============================================================
    def fetch_alerts(self, target_url):
        result = self._call("core/view/alerts", {
            "baseurl": target_url,
            "start": 0,
            "count": 1000
        })
        if result and result.get("alerts"):
            return result["alerts"]
        return []

    # ============================================================
    # NORMALIZE
    # ============================================================
    def normalize_alert(self, alert, asset_id="nexora_website"):
        risk_map = {
            "High": "critical",
            "Medium": "high",
            "Low": "medium",
            "Informational": "low"
        }
        severity = risk_map.get(alert.get("risk", "Low"), "low")

        # Extract CVE
        cve_id = None
        tags = alert.get("tags", {})
        for key in tags.keys():
            if key.startswith("CVE-"):
                cve_id = key
                break

        return {
            "finding_id": f"zap_{uuid.uuid4().hex[:8]}",
            "asset_id": asset_id,
            "source": "zap",
            "cve_id": cve_id,
            "title": alert.get("name", "ZAP Finding"),
            "description": alert.get("description", ""),
            "severity": severity,
            "raw_data": json.dumps(alert)
        }

    # ============================================================
    # MAIN PIPELINE
    # ============================================================
    def run(self, target_url=None, asset_id="nexora_website",
            account_name="admin", use_ajax=True, use_active=True):
        if not target_url:
            target_url = os.getenv('ZAP_TARGET_URL', '')

        logger.info("=" * 60)
        logger.info(f"🚀 ZAP — {target_url}")
        logger.info(f"   Account: {account_name} | AJAX: {use_ajax} | Active: {use_active}")
        logger.info("=" * 60)

        # 1. Setup authentication
        self.setup_authenticated_context(target_url, account_name)

        # 2. Spider
        if use_ajax:
            spider_id = self.start_ajax_spider(target_url)
            if spider_id:
                self.wait_for_ajax_spider(spider_id)

        # 3. Active scan
        if use_active:
            ascan_id = self.start_active_scan(target_url)
            if ascan_id:
                self.wait_for_active_scan(ascan_id)

        # 4. Fetch alerts
        alerts = self.fetch_alerts(target_url)
        logger.info(f"📊 Found {len(alerts)} alerts")

        # 5. Store in DB
        count = 0
        for alert in alerts:
            try:
                norm = self.normalize_alert(alert, asset_id=asset_id)
                query = """
                    INSERT INTO findings
                        (finding_id, asset_id, source, cve_id, title, description, severity, raw_data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (finding_id) DO NOTHING
                """
                db.execute_query(query, (
                    norm["finding_id"], norm["asset_id"], norm["source"],
                    norm["cve_id"], norm["title"], norm["description"],
                    norm["severity"], norm["raw_data"]
                ))
                count += 1
            except Exception as e:
                logger.error(f"❌ Failed: {e}")

        logger.info(f"✅ ZAP: {count} findings ingested")

        return {
            "source": "zap",
            "findings_ingested": count,
            "target": target_url,
            "account": account_name,
            "total_alerts": len(alerts)
        }


if __name__ == "__main__":
    ingestor = ZAPIngestor()

    # Nexora website — admin account
    result = ingestor.run(
        target_url="https://desktop-72ti05t.tailc1051b.ts.net/",
        asset_id="nexora_website",
        account_name="admin",
        use_ajax=True,
        use_active=True
    )
    print(json.dumps(result, indent=2))