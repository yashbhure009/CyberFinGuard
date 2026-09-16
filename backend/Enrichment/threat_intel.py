"""
Threat Intelligence Enricher
Fetches CVSS (NVD), EPSS, and CISA KEV data
"""

import os
import sys
import json
import logging
import time
from datetime import datetime
import requests
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from database import db
except ImportError:
    from backend.database import db

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatIntelEnricher:
    def __init__(self):
        self.nvd_api_url = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
        self.nvd_api_key = os.getenv("NVD_API_KEY", "")
        self.epss_api_url = os.getenv("EPSS_API_URL", "https://api.first.org/data/v1/epss")
        self.cisa_kev_url = os.getenv("CISA_KEV_URL", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
        self._kev_set = None

    def get_cvss(self, cve_id: str):
        """Fetch CVSS score from NVD"""
        if not cve_id:
            return None, "UNKNOWN"
        headers = {}
        if self.nvd_api_key:
            headers["apiKey"] = self.nvd_api_key
        try:
            resp = requests.get(self.nvd_api_url, params={"cveId": cve_id}, headers=headers, timeout=10)
            if resp.ok:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    metrics = vulns[0].get("cve", {}).get("metrics", {})
                    # Try v31, v30, v2
                    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                        if key in metrics and metrics[key]:
                            cvss_data = metrics[key][0].get("cvssData", {})
                            score = cvss_data.get("baseScore")
                            severity = cvss_data.get("baseSeverity", "UNKNOWN")
                            return float(score) if score is not None else None, severity
        except Exception as e:
            logger.error(f"NVD error for {cve_id}: {e}")
        return None, "UNKNOWN"

    def get_epss(self, cve_ids: list):
        """Fetch EPSS scores for multiple CVEs"""
        if not cve_ids:
            return {}
        scores = {}
        try:
            cve_str = ",".join(cve_ids[:100])
            resp = requests.get(self.epss_api_url, params={"cve": cve_str}, timeout=10)
            if resp.ok:
                items = resp.json().get("data", [])
                for item in items:
                    cve = item.get("cve")
                    epss = item.get("epss")
                    if cve and epss is not None:
                        scores[cve] = float(epss)
        except Exception as e:
            logger.error(f"EPSS error: {e}")
        return scores

    def get_cisa_kev(self):
        """Fetch CISA KEV list (cached)"""
        if self._kev_set is not None:
            return self._kev_set
        logger.info("🛡️ Fetching CISA KEV list...")
        self._kev_set = set()
        try:
            resp = requests.get(self.cisa_kev_url, timeout=10)
            if resp.ok:
                vulns = resp.json().get("vulnerabilities", [])
                for item in vulns:
                    cve = item.get("cveID")
                    if cve:
                        self._kev_set.add(cve)
                logger.info(f"✅ Loaded {len(self._kev_set)} KEV entries")
        except Exception as e:
            logger.error(f"CISA KEV error: {e}")
        return self._kev_set

    def enrich_finding(self, cve_id: str):
        """Enrich a single CVE"""
        cvss, severity = self.get_cvss(cve_id)
        epss_map = self.get_epss([cve_id])
        epss = epss_map.get(cve_id)
        kev_set = self.get_cisa_kev()
        is_kev = cve_id in kev_set if cve_id else False
        return {
            "cve_id": cve_id,
            "cvss_score": cvss,
            "epss_score": epss,
            "cisa_kev": is_kev,
            "severity": severity
        }

    def enrich_database_findings(self):
        """Enrich all findings in DB"""
        query = """
            SELECT finding_id, cve_id, cvss_score, epss_score, cisa_kev
            FROM findings
            WHERE cve_id IS NOT NULL
        """
        findings = db.execute_query(query)
        if not findings:
            logger.info("No findings with CVE IDs found")
            return 0

        logger.info(f"Found {len(findings)} findings to enrich")
        cve_ids = list({f['cve_id'] for f in findings if f.get('cve_id')})
        logger.info(f"Unique CVEs: {len(cve_ids)}")

        logger.info("Fetching EPSS scores (batch)...")
        epss_map = self.get_epss(cve_ids)
        kev_set = self.get_cisa_kev()

        count = 0
        for f in findings:
            cve_id = f['cve_id']
            try:
                cvss_score = f.get('cvss_score')
                if cvss_score is None:
                    cvss_score, _ = self.get_cvss(cve_id)

                epss_score = epss_map.get(cve_id, f.get('epss_score'))
                is_kev = cve_id in kev_set

                update_query = """
                    UPDATE findings
                    SET cvss_score = %s, epss_score = %s, cisa_kev = %s
                    WHERE finding_id = %s
                """
                db.execute_query(update_query, (cvss_score, epss_score, is_kev, f['finding_id']))
                count += 1
                logger.info(f"Enriched {cve_id}: CVSS={cvss_score}, EPSS={epss_score}, KEV={is_kev}")
            except Exception as e:
                logger.error(f"Failed to enrich {f['finding_id']}: {e}")

        return count


if __name__ == "__main__":
    enricher = ThreatIntelEnricher()
    print(enricher.enrich_database_findings())
