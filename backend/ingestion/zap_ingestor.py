"""
OWASP ZAP Data Ingestor
Pulls findings from ZAP API
"""

"""
OWASP ZAP Data Ingestor - Real Scan Version
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


class ZAPIngestor:
    def __init__(self):
        self.zap_url = os.getenv('ZAP_API_URL', 'http://localhost:8080')
        self.api_key = os.getenv('ZAP_API_KEY', '')
        self.target_url = os.getenv('ZAP_TARGET_URL', 'https://httpbin.org')
        self.session = requests.Session()

    def _call(self, endpoint, params=None):
        """ZAP API call helper"""
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

    def start_spider(self, target_url):
        """Start spider scan"""
        result = self._call("spider/action/scan", {"url": target_url})
        if result and "scan" in result:
            return result["scan"]
        return None

    def wait_for_spider(self, scan_id, timeout=120):
        """Wait for spider to complete"""
        start_time = time.time()
        while time.time() - start_time < timeout:
            result = self._call("spider/view/status", {"scanId": scan_id})
            if result and "status" in result:
                status = int(result["status"])
                logger.info(f"🕷️ Spider progress: {status}%")
                if status >= 100:
                    return True
            time.sleep(3)
        return False

    def fetch_alerts(self, target_url):
        """Fetch alerts from ZAP API"""
        result = self._call("core/view/alerts", {"baseurl": target_url})
        if result and result.get("alerts"):
            return result.get("alerts")
        logger.warning("⚠️ No alerts found")
        return []

    def normalize_alert(self, alert):
        """Convert ZAP alert to unified schema"""
        risk_map = {
            "High": "critical",
            "Medium": "high",
            "Low": "medium",
            "Informational": "low"
        }
        severity = risk_map.get(alert.get("risk", "Low"), "low")
        
        return {
            "finding_id": f"zap_{uuid.uuid4().hex[:8]}",
            "asset_id": "httpbin_target",
            "source": "zap",
            "title": alert.get("name", "ZAP Finding"),
            "description": alert.get("description", ""),
            "severity": severity,
            "raw_data": json.dumps(alert)
        }

    def run(self, target_url=None):
        """Run full ZAP scan pipeline"""
        if not target_url:
            target_url = self.target_url
        
        logger.info(f"🚀 Starting ZAP scan on {target_url}")
        
        # Step 1: Spider scan
        logger.info("🕷️ Starting spider scan...")
        spider_id = self.start_spider(target_url)
        if spider_id:
            logger.info(f"🕷️ Spider scan ID: {spider_id}")
            self.wait_for_spider(spider_id)
            logger.info("✅ Spider scan complete")
        else:
            logger.warning("⚠️ Spider scan failed to start")
        
        # Step 2: Fetch alerts
        logger.info("📊 Fetching alerts...")
        alerts = self.fetch_alerts(target_url)
        logger.info(f"📊 Found {len(alerts)} alerts")
        
        # Step 3: Store in database
        count = 0
        for alert in alerts:
            try:
                norm = self.normalize_alert(alert)
                query = """
                    INSERT INTO findings (finding_id, asset_id, source, title, description, severity, raw_data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (finding_id) DO NOTHING
                """
                db.execute_query(query, (
                    norm["finding_id"], norm["asset_id"], norm["source"],
                    norm["title"], norm["description"], norm["severity"], norm["raw_data"]
                ))
                count += 1
                logger.info(f"✅ Ingested: {norm['title'][:60]}")
            except Exception as e:
                logger.error(f"❌ Failed to ingest: {e}")
        
        return {"source": "zap", "findings_ingested": count, "target": target_url}


if __name__ == "__main__":
    ingestor = ZAPIngestor()
    print(ingestor.run())