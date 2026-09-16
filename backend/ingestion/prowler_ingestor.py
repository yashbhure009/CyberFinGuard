"""
Prowler Ingestor Module
Executes Prowler CSPM scan over SSH or ingests results
"""

import os
import sys
import json
import logging
import csv
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


class ProwlerConfig:
    def __init__(self):
        self.ssh_host = os.getenv("KALI_HOST", "")
        self.ssh_port = int(os.getenv("KALI_SSH_PORT", "22"))
        self.ssh_username = os.getenv("KALI_USERNAME", "kali")
        self.ssh_password = os.getenv("KALI_SSH_PASSWORD", "")
        self.prowler_dir = os.getenv("PROWLER_DIR", "/home/kali/prowler")
        self.services = os.getenv("PROWLER_SERVICES", "iam")
        self.output_dir = "data/prowler_results"


class ProwlerIngestor:
    def __init__(self, config: ProwlerConfig = None):
        self.config = config or ProwlerConfig()
        self.ssh_client = None

    def connect_ssh(self):
        """Connect to Kali via SSH if configured."""
        if not configured(self.config.ssh_host) or not configured(self.config.ssh_password):
            raise RuntimeError("KALI_HOST and KALI_SSH_PASSWORD required for Prowler collection.")
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
            logger.info("Connected to Kali for Prowler scan.")
            return True
        except Exception as e:
            logger.error(f"Prowler SSH connection failed: {e}")
            raise

    def run(self):
        """Run Prowler collection and ingest findings."""
        if not configured(self.config.ssh_host):
            logger.info("Prowler not configured. Skipping live collection.")
            return {"source": "prowler", "status": "not_configured", "findings_count": 0}

        try:
            self.connect_ssh()
            stdin, stdout, stderr = self.ssh_client.exec_command(
                f"cd {self.config.prowler_dir} && source .venv/bin/activate && prowler aws --services {self.config.services} --json",
                timeout=300
            )
            out_str = stdout.read().decode("utf-8", "replace")
            self.ssh_client.close()
            
            count = 0
            for line in out_str.splitlines():
                if not line.strip() or not line.startswith("{"):
                    continue
                try:
                    record = json.loads(line)
                    if record.get("Status") == "FAIL":
                        resource_uid = record.get("ResourceUid", "prowler-aws-resource")
                        asset_id = stable_id("prowler", resource_uid)
                        finding_id = stable_id("prowler", asset_id, record.get("CheckId", ""))
                        finding = {
                            "finding_id": finding_id,
                            "asset_id": asset_id,
                            "asset_name": record.get("ResourceName", resource_uid),
                            "asset_type": "cloud_account",
                            "source": "prowler",
                            "title": record.get("CheckTitle", record.get("CheckId", "Prowler Finding")),
                            "description": record.get("Description", ""),
                            "severity": (record.get("Severity") or "medium").lower(),
                            "raw_data": record
                        }
                        if insert_finding(finding):
                            count += 1
                except Exception as parse_e:
                    logger.warning(f"Prowler parse error: {parse_e}")

            return {"source": "prowler", "status": "success", "new_findings": count}
        except Exception as e:
            logger.error(f"Prowler ingestion failed: {e}")
            return {"source": "prowler", "status": "failed", "error": str(e)}


if __name__ == "__main__":
    ingestor = ProwlerIngestor()
    print(ingestor.run())
