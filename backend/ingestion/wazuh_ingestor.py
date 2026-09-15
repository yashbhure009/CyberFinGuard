import requests, json, logging, uuid, os, sys, urllib3
from datetime import datetime
from dotenv import load_dotenv

urllib3.disable_warnings()
load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WazuhIngestor:
    def __init__(self):
        self.api_url = os.getenv("WAZUH_API_URL")
        self.username = os.getenv("WAZUH_USERNAME")
        self.password = os.getenv("WAZUH_PASSWORD")
        self.indexer_url = os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200")
        self.indexer_user = os.getenv("WAZUH_INDEXER_USER", "admin")
        self.indexer_pass = os.getenv("WAZUH_INDEXER_PASSWORD")

    def _token(self):
        r = requests.post(
            f"{self.api_url}/security/user/authenticate?raw=true",
            auth=(self.username, self.password),
            verify=False, timeout=10,
        )
        r.raise_for_status()
        return r.text.strip()

    def fetch_agents(self):
        try:
            token = self._token()
            headers = {"Authorization": f"Bearer {token}"}
            r = requests.get(f"{self.api_url}/agents",
                             headers=headers, verify=False, timeout=15)
            logger.info(f"agents HTTP status: {r.status_code}")
            data = r.json()
            items = data.get("data", {}).get("affected_items", [])
            logger.info(f"agents count: {len(items)}")
            return items
        except Exception as e:
            logger.warning(f"agents fetch failed: {type(e).__name__}: {e}")
            return []

    def fetch_alerts(self, limit=100):
        try:
            url = f"{self.indexer_url}/wazuh-alerts-*/_search"
            query = {
                "size": limit,
                "sort": [{"@timestamp": {"order": "desc"}}],
                "query": {"match_all": {}}
            }
            r = requests.get(url,
                             auth=(self.indexer_user, self.indexer_pass),
                             json=query,
                             verify=False, timeout=15)
            r.raise_for_status()
            hits = r.json().get("hits", {}).get("hits", [])
            return [h.get("_source", {}) for h in hits]
        except Exception as e:
            logger.warning(f"alerts fetch failed: {e}")
            return []

    def _severity(self, level):
        if level >= 12:
            return "critical"
        if level >= 9:
            return "high"
        if level >= 6:
            return "medium"
        if level >= 3:
            return "low"
        return "info"

    def _mitre(self, rule):
        """Extract first MITRE technique ID from rule.mitre.id."""
        mitre = rule.get("mitre", {})
        if not isinstance(mitre, dict):
            return None
        ids = mitre.get("id", [])
        if isinstance(ids, list) and ids:
            return ids[0][:20]   # column is VARCHAR(20)
        return None

    def _ensure_asset(self, aid, name, ip):
        if not db.execute_query("SELECT asset_id FROM assets WHERE asset_id=%s", (aid,)):
            db.execute_query(
                """INSERT INTO assets (asset_id, asset_name, asset_type, ip_address,
                   hostname, environment, production_status, criticality, asset_value)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (aid, name, "server", ip, name, "unknown", "unknown", 3, 10000000))
            return True
        return False

    def sync_agents(self):
        n = 0
        for a in self.fetch_agents():
            aid = f"agent_{a.get('id', 'unknown')}"
            if self._ensure_asset(aid, a.get("name", "unknown"), a.get("ip", "unknown")):
                n += 1
                logger.info(f"Synced asset: {a.get('name')}")
        return n

    def ingest_alerts(self):
        n = 0
        mitre_count = 0
        for alert in self.fetch_alerts():
            agent = alert.get("agent", {})
            agent_id = agent.get("id")
            if not agent_id:
                continue

            rule = alert.get("rule", {})
            fid = f"wazuh_{alert.get('id', uuid.uuid4().hex[:8])}"
            aid = f"agent_{agent_id}"
            mitre = self._mitre(rule)

            self._ensure_asset(aid, agent.get("name", "unknown"), agent.get("ip", "unknown"))

            try:
                db.execute_query(
                    """INSERT INTO findings (finding_id, asset_id, source, title,
                       description, severity, mitre_technique, raw_data)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
                       ON CONFLICT (finding_id) DO NOTHING""",
                    (fid, aid, "wazuh",
                     rule.get("description", "Wazuh Alert"),
                     alert.get("full_log", ""),
                     self._severity(rule.get("level", 0)),
                     mitre,
                     json.dumps(alert)))
                n += 1
                if mitre:
                    mitre_count += 1
            except Exception as e:
                logger.error(f"alert insert failed: {e}")
        logger.info(f"MITRE techniques found: {mitre_count}")
        return n

    def run(self):
        a = self.sync_agents()
        f = self.ingest_alerts()
        logger.info(f"Done: {a} new assets, {f} alerts")
        return {"assets": a, "alerts": f}


if __name__ == "__main__":
    print(WazuhIngestor().run())