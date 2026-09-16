"""
Nmap Data Ingestor
Runs Nmap scan and stores results in database
"""

import os
import sys
import json
import logging
import subprocess
import xml.etree.ElementTree as ET
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


class NmapIngestor:
    def __init__(self):
        self.nmap_path = os.getenv("NMAP_PATH", r"C:\Program Files (x86)\Nmap\nmap.exe")

    def run_scan(self, target: str) -> str:
        """Run Nmap CLI scan and return XML output string or path."""
        target_host = require_authorized_target(target)
        cmd = [self.nmap_path, "-F", "-sV", "-oX", "-", target_host]
        logger.info(f"Running Nmap: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300, check=True)
        return result.stdout

    def parse_xml(self, xml_content: str, target_host: str):
        """Parse Nmap XML output into normalized findings."""
        findings = []
        try:
            root = ET.fromstring(xml_content)
            for host in root.findall("host"):
                ip = None
                for addr in host.findall("address"):
                    if addr.get("addrtype") == "ipv4":
                        ip = addr.get("addr")
                        break
                asset_id = stable_id("nmap", ip or target_host)
                ports = host.find("ports")
                if ports is None:
                    continue
                for port in ports.findall("port"):
                    state = port.find("state")
                    if state is not None and state.get("state") == "open":
                        port_id = port.get("portid")
                        protocol = port.get("protocol", "tcp")
                        service = port.find("service")
                        service_name = service.get("name", "unknown") if service is not None else "unknown"
                        product = service.get("product", "") if service is not None else ""
                        version = service.get("version", "") if service is not None else ""
                        
                        finding_id = stable_id("nmap", asset_id, port_id, protocol)
                        title = f"Open Port {port_id}/{protocol} - {service_name}"
                        desc = f"Service '{service_name}' ({product} {version}) is accessible on port {port_id}/{protocol}."
                        
                        findings.append({
                            "finding_id": finding_id,
                            "asset_id": asset_id,
                            "asset_name": target_host,
                            "asset_type": "network_target",
                            "ip_address": ip,
                            "source": "nmap",
                            "title": title,
                            "description": desc,
                            "severity": "info",
                            "raw_data": {
                                "port": port_id,
                                "protocol": protocol,
                                "service": service_name,
                                "product": product,
                                "version": version
                            }
                        })
        except Exception as e:
            logger.error(f"Failed to parse Nmap XML: {e}")
        return findings

    def run(self, target: str = None):
        """Run full Nmap ingestion pipeline."""
        if not target:
            auth_targets = [t.strip() for t in os.getenv("AUTHORIZED_SCAN_TARGETS", "").split(",") if t.strip()]
            target = auth_targets[0] if auth_targets else "scanme.nmap.org"
        logger.info(f"🚀 Running Nmap ingestor for target: {target}")
        try:
            xml_data = self.run_scan(target)
            findings = self.parse_xml(xml_data, target)
            count = 0
            for f in findings:
                if insert_finding(f):
                    count += 1
            return {"source": "nmap", "target": target, "findings_count": len(findings), "new_findings": count}
        except Exception as e:
            logger.error(f"❌ Nmap scan failed: {e}")
            return {"source": "nmap", "error": str(e)}


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "scanme.nmap.org"
    ingestor = NmapIngestor()
    print(ingestor.run(target))
