"""
Nuclei Data Ingestor
Runs Nuclei scan and stores findings in database
"""

import os
import sys
import json
import logging
import subprocess
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from database import db
except ImportError:
    from backend.database import db

try:
    from ingestion.common import require_authorized_target, stable_id, insert_finding
except ModuleNotFoundError:
    from backend.ingestion.common import require_authorized_target, stable_id, insert_finding

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NucleiIngestor:
    def __init__(self):
        self.nuclei_path = os.getenv("NUCLEI_PATH", r"D:\Tools\Nuclei\nuclei.exe")

    def run_scan(self, target: str) -> str:
        """Run Nuclei CLI scan and return JSON output."""
        target_host = require_authorized_target(target)
        target_url = target if "://" in target else f"https://{target_host}"
        cmd = [self.nuclei_path, "-u", target_url, "-json-export", "-"]
        logger.info(f"Running Nuclei: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600, check=False)
        return result.stdout

    def parse_json(self, json_output: str, target: str):
        """Parse Nuclei JSON output into normalized findings."""
        findings = []
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "info"
        }
        for line in json_output.splitlines():
            line = line.strip()
            if not line or not line.startswith("{"):
                continue
            try:
                item = json.loads(line)
                info = item.get("info", {})
                template_id = item.get("template-id", "nuclei-finding")
                matched_at = item.get("matched-at", target)
                sev = info.get("severity", "info").lower()
                cve_id = None
                cls = info.get("classification", {})
                if cls and isinstance(cls, dict):
                    cve_list = cls.get("cve-id", [])
                    if cve_list and isinstance(cve_list, list):
                        cve_id = cve_list[0]
                
                asset_id = stable_id("nuclei", target)
                finding_id = stable_id("nuclei", asset_id, template_id, matched_at)
                title = info.get("name", template_id)
                desc = info.get("description", f"Matched at: {matched_at}")

                findings.append({
                    "finding_id": finding_id,
                    "asset_id": asset_id,
                    "asset_name": target,
                    "asset_type": "website",
                    "source": "nuclei",
                    "cve_id": cve_id,
                    "title": title,
                    "description": desc,
                    "severity": severity_map.get(sev, "info"),
                    "raw_data": item
                })
            except Exception as e:
                logger.error(f"Failed to parse Nuclei line: {e}")
        return findings

    def run(self, target: str = None):
        """Run full Nuclei ingestion pipeline."""
        if not target:
            auth_targets = [t.strip() for t in os.getenv("AUTHORIZED_SCAN_TARGETS", "").split(",") if t.strip()]
            target = auth_targets[0] if auth_targets else "https://httpbin.org"
        logger.info(f"🚀 Running Nuclei ingestor for target: {target}")
        try:
            output = self.run_scan(target)
            findings = self.parse_json(output, target)
            count = 0
            for f in findings:
                if insert_finding(f):
                    count += 1
            return {"source": "nuclei", "target": target, "findings_count": len(findings), "new_findings": count}
        except Exception as e:
            logger.error(f"❌ Nuclei scan failed: {e}")
            return {"source": "nuclei", "error": str(e)}


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "https://httpbin.org"
    ingestor = NucleiIngestor()
    print(ingestor.run(target))
