"""
Nuclei Data Ingestor
Runs Nuclei scan and stores findings in database
"""

import subprocess
import json
import logging
import uuid
import os
import sys
from datetime import datetime
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import db

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Nuclei path from .env
NUCLEI_PATH = r'D:\Tools\Nuclei\nuclei.exe'


class NucleiIngestor:
    def __init__(self):
        self.asset_id = 'web_target'

    def run_scan(self, target, severity='medium,high,critical'):
        """Run Nuclei scan and save JSON output"""
        output_file = f'nuclei_{target.replace("://", "_").replace("/", "_").replace(".", "_")}.json'
        
        cmd = [
            NUCLEI_PATH,
            '-u', target,
            '-severity', severity,
            '-jsonl',
            '-o', output_file
        ]
        
        logger.info(f"🚀 Running Nuclei scan on {target}...")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=900  # 15 minutes
            )
            
            if result.returncode == 0:
                logger.info(f"✅ Scan complete: {output_file}")
                return output_file
            else:
                logger.error(f"❌ Scan failed: {result.stderr[:200]}")
                return None
        except subprocess.TimeoutExpired:
            logger.error("❌ Scan timeout (15 min)")
            return None
        except Exception as e:
            logger.error(f"❌ Scan error: {e}")
            return None

    def parse_json(self, json_file):
        """Parse Nuclei JSON output"""
        if not os.path.exists(json_file):
            logger.error(f"❌ File not found: {json_file}")
            return []
        
        findings = []
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        finding = json.loads(line)
                        findings.append(finding)
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            logger.error(f"❌ JSON parse error: {e}")
        
        return findings

    def normalize_finding(self, finding):
        """Convert Nuclei finding to unified schema"""
        info = finding.get('info', {})
        severity = info.get('severity', 'low')
        
        severity_map = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'info': 'info',
            'unknown': 'info'
        }
        
        # Extract CVE from classification
        classification = info.get('classification', {})
        cve_ids = classification.get('cve-id', [])
        cve_id = cve_ids[0] if cve_ids else None
        
        return {
            'finding_id': f"nuclei_{uuid.uuid4().hex[:8]}",
            'asset_id': self.asset_id,
            'source': 'nuclei',
            'cve_id': cve_id,
            'title': info.get('name', 'Nuclei Finding'),
            'description': info.get('description', '') or f"Matched at: {finding.get('matched-at', 'unknown')}",
            'severity': severity_map.get(severity, 'info'),
            'raw_data': json.dumps(finding)
        }

    def ingest(self, json_file):
        """Parse JSON and store findings in DB"""
        findings = self.parse_json(json_file)
        logger.info(f"📊 Found {len(findings)} Nuclei findings")
        
        count = 0
        for finding in findings:
            try:
                norm = self.normalize_finding(finding)
                
                query = """
                    INSERT INTO findings (finding_id, asset_id, source, cve_id, title, description, severity, raw_data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (finding_id) DO NOTHING
                """
                db.execute_query(query, (
                    norm['finding_id'], norm['asset_id'], norm['source'],
                    norm['cve_id'], norm['title'], norm['description'],
                    norm['severity'], norm['raw_data']
                ))
                count += 1
                logger.info(f"✅ Ingested: {norm['title'][:60]}")
            except Exception as e:
                logger.error(f"❌ Failed: {e}")
        
        return {'source': 'nuclei', 'findings_ingested': count}

    def run(self, target='http://localhost:3000'):
        """Full pipeline: scan → parse → ingest"""
        json_file = self.run_scan(target)
        if not json_file:
            return {'source': 'nuclei', 'error': 'scan_failed'}
        return self.ingest(json_file)


if __name__ == "__main__":
    ingestor = NucleiIngestor()
    
    # Target select karo
    target = input("Enter target URL (default: https://httpbin.org): ").strip()
    if not target:
        target = 'https://httpbin.org'
    
    result = ingestor.run(target)
    print(result)