"""
ZAP Manual Scan — Direct URL Scan (No Auth)
Nexora ke public pages scan karo
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


class ZAPManualScan:
    def __init__(self):
        self.zap_url = os.getenv('ZAP_API_URL', 'http://localhost:8080')
        self.session = requests.Session()

    def _call(self, endpoint, params=None):
        url = f"{self.zap_url}/JSON/{endpoint}/"
        if params is None:
            params = {}
        try:
            response = self.session.get(url, params=params, timeout=60)
            return response.json()
        except Exception as e:
            logger.error(f"ZAP API error: {e}")
            return None

    def scan_url(self, target_url):
        """Scan a single URL — passive only (fast)"""
        logger.info(f"🔍 Scanning: {target_url}")

        # 1. Access URL (passive scan trigger)
        self._call("core/action/accessUrl", {"url": target_url})

        # 2. Wait for passive scan
        time.sleep(5)

        # 3. Get alerts for this URL
        result = self._call("core/view/alerts", {
            "baseurl": target_url,
            "start": 0,
            "count": 500
        })

        alerts = result.get("alerts", []) if result else []
        logger.info(f"📊 {target_url} → {len(alerts)} alerts")
        return alerts

    def run(self, base_url, paths=None):
        """Scan multiple paths"""
        if paths is None:
            paths = [
                "/",
                "/login",
                "/solutions",
                "/products",
                "/industries",
                "/resources",
                "/company",
                "/portal",
                "/admin",
                "/api/products",
                "/api/orders",
            ]

        all_alerts = []
        for path in paths:
            url = f"{base_url.rstrip('/')}{path}"
            alerts = self.scan_url(url)
            all_alerts.extend(alerts)

        logger.info(f"📊 Total alerts: {len(all_alerts)}")

        # Store in DB
        count = 0
        for alert in all_alerts:
            try:
                finding = self.normalize(alert)
                query = """
                    INSERT INTO findings
                        (finding_id, asset_id, source, cve_id, title, description, severity, raw_data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (finding_id) DO NOTHING
                """
                db.execute_query(query, (
                    finding["finding_id"], finding["asset_id"], finding["source"],
                    finding["cve_id"], finding["title"], finding["description"],
                    finding["severity"], finding["raw_data"]
                ))
                count += 1
            except Exception as e:
                logger.error(f"❌ DB error: {e}")

        logger.info(f"✅ Ingested {count} findings")
        return {"source": "zap", "findings_ingested": count, "total_alerts": len(all_alerts)}

    def normalize(self, alert):
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
            "asset_id": "nexora_website",
            "source": "zap",
            "cve_id": cve_id,
            "title": alert.get("name", "ZAP Finding"),
            "description": alert.get("description", ""),
            "severity": severity,
            "raw_data": json.dumps(alert)
        }


if __name__ == "__main__":
    scanner = ZAPManualScan()
    result = scanner.run("https://desktop-72ti05t.tailc1051b.ts.net/")
    print(json.dumps(result, indent=2))