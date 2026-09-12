"""
Threat Intelligence Enricher
Fetches CVSS (NVD), EPSS, and CISA KEV data
"""

import requests
import json
import logging
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatIntelEnricher:
    def __init__(self):
        self.nvd_url = os.getenv('NVD_API_URL', 'https://services.nvd.nist.gov/rest/json/cves/2.0')
        self.epss_url = os.getenv('EPSS_API_URL', 'https://api.first.org/data/v1/epss')
        self.cisa_kev_url = os.getenv('CISA_KEV_URL', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json')
        self.kev_cache = None

    def get_cvss(self, cve_id):
        """Fetch CVSS score from NVD"""
        try:
            response = requests.get(
                self.nvd_url,
                params={'cveId': cve_id},
                timeout=15
            )
            data = response.json()
            
            if data.get('vulnerabilities'):
                cve = data['vulnerabilities'][0]['cve']
                metrics = cve.get('metrics', {})
                
                for version in ['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                    if version in metrics:
                        cvss_data = metrics[version][0]['cvssData']
                        return {
                            'score': cvss_data['baseScore'],
                            'severity': cvss_data.get('baseSeverity', 'UNKNOWN'),
                            'version': version
                        }
            return None
        except Exception as e:
            logger.error(f"NVD error for {cve_id}: {e}")
            return None

    def get_epss(self, cve_ids):
        """Fetch EPSS scores for multiple CVEs"""
        if not cve_ids:
            return {}
        
        try:
            response = requests.get(
                self.epss_url,
                params={'cve': ','.join(cve_ids)},
                timeout=30
            )
            data = response.json()
            return {item['cve']: float(item['epss']) for item in data.get('data', [])}
        except Exception as e:
            logger.error(f"EPSS error: {e}")
            return {}

    def get_cisa_kev(self):
        """Fetch CISA KEV list (cached)"""
        if self.kev_cache is not None:
            return self.kev_cache
        
        try:
            logger.info("📥 Fetching CISA KEV list...")
            response = requests.get(self.cisa_kev_url, timeout=30)
            data = response.json()
            self.kev_cache = {v['cveID']: v for v in data.get('vulnerabilities', [])}
            logger.info(f"✅ Loaded {len(self.kev_cache)} KEV entries")
            return self.kev_cache
        except Exception as e:
            logger.error(f"CISA KEV error: {e}")
            return {}

    def enrich_finding(self, cve_id):
        """Enrich a single CVE"""
        cvss = self.get_cvss(cve_id)
        epss = self.get_epss([cve_id]).get(cve_id)
        kev = cve_id in self.get_cisa_kev()
        
        return {
            'cve_id': cve_id,
            'cvss_score': cvss['score'] if cvss else None,
            'cvss_severity': cvss['severity'] if cvss else None,
            'epss_score': epss,
            'cisa_kev': kev,
            'enriched_at': datetime.now().isoformat()
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
            logger.info("ℹ️ No findings with CVE IDs found")
            return 0
        
        logger.info(f"📊 Found {len(findings)} findings to enrich")
        
        cve_ids = list(set([f['cve_id'] for f in findings if f['cve_id']]))
        logger.info(f"🔍 Unique CVEs: {len(cve_ids)}")
        
        logger.info("📥 Fetching EPSS scores (batch)...")
        epss_scores = self.get_epss(cve_ids)
        
        kev_list = self.get_cisa_kev()
        
        count = 0
        for finding in findings:
            cve_id = finding['cve_id']
            if not cve_id:
                continue
            
            try:
                cvss_data = self.get_cvss(cve_id)
                cvss_score = cvss_data['score'] if cvss_data else finding.get('cvss_score')
                epss_score = epss_scores.get(cve_id, finding.get('epss_score'))
                is_kev = cve_id in kev_list
                
                update_query = """
                    UPDATE findings
                    SET cvss_score = %s, epss_score = %s, cisa_kev = %s
                    WHERE finding_id = %s
                """
                db.execute_query(update_query, (cvss_score, epss_score, is_kev, finding['finding_id']))
                count += 1
                
                logger.info(f"✅ Enriched {cve_id}: CVSS={cvss_score}, EPSS={epss_score}, KEV={is_kev}")
                time.sleep(6)  # Rate limit
                
            except Exception as e:
                logger.error(f"❌ Failed to enrich {cve_id}: {e}")
                continue
        
        return count


if __name__ == "__main__":
    print("=" * 60)
    print("🚀 Threat Intelligence Enricher")
    print("=" * 60)
    
    enricher = ThreatIntelEnricher()
    
    # Test single CVE
    print("\n🧪 Testing single CVE enrichment...")
    result = enricher.enrich_finding("CVE-2021-41773")
    print(json.dumps(result, indent=2))
    
    # Enrich DB findings
    print("\n📊 Enriching database findings...")
    count = enricher.enrich_database_findings()
    print(f"\n✅ Enriched {count} findings")