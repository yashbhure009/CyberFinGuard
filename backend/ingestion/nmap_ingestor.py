"""
Nmap Data Ingestor
Runs Nmap scan and stores results in database
"""

import subprocess
import json
import logging
import uuid
import os
import sys
import xml.etree.ElementTree as ET
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from database import db

load_dotenv()

# Nmap path from .env
NMAP_PATH = os.getenv('NMAP_PATH', r'C:\Program Files (x86)\Nmap\nmap.exe')

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class NmapIngestor:
    def __init__(self):
        self.asset_id = 'network_target'

    def run_scan(self, target, scan_type='quick'):
        """Run Nmap scan and return XML output"""
        scan_args = {
            'quick': ['-F', '-sV', '-T4'],
            'full': ['-p-', '-sV', '-sC', '-T4'],
        }
        
        args = scan_args.get(scan_type, scan_args['quick'])
        output_file = f'nmap_{target.replace(".", "_")}.xml'
        
        cmd = [NMAP_PATH] + args + ['-oX', output_file, target]
        
        logger.info(f"🚀 Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode == 0:
                logger.info(f"✅ Scan complete: {output_file}")
                return output_file
            else:
                logger.error(f"❌ Scan failed: {result.stderr}")
                return None
        except Exception as e:
            logger.error(f"❌ Scan error: {e}")
            return None

    def parse_xml(self, xml_file):
        """Parse Nmap XML output"""
        if not os.path.exists(xml_file):
            logger.error(f"❌ File not found: {xml_file}")
            return []
        
        findings = []
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for host in root.findall('host'):
                address = host.find('address')
                if address is None:
                    continue
                ip = address.get('addr')
                
                status = host.find('status')
                if status is not None and status.get('state') != 'up':
                    continue
                
                ports = host.find('ports')
                if ports is None:
                    continue
                
                for port in ports.findall('port'):
                    state = port.find('state')
                    if state is None or state.get('state') != 'open':
                        continue
                    
                    port_id = port.get('portid')
                    protocol = port.get('protocol')
                    
                    service = port.find('service')
                    service_name = service.get('name', 'unknown') if service is not None else 'unknown'
                    service_version = service.get('version', '') if service is not None else ''
                    service_product = service.get('product', '') if service is not None else ''
                    
                    findings.append({
                        'finding_id': f"nmap_{uuid.uuid4().hex[:8]}",
                        'asset_id': self.asset_id,
                        'source': 'nmap',
                        'title': f"Open Port: {port_id}/{protocol} ({service_name})",
                        'description': f"Service: {service_product} {service_version}".strip(),
                        'severity': self._severity_from_port(port_id),
                        'raw_data': json.dumps({
                            'ip': ip, 'port': port_id, 'protocol': protocol,
                            'service': service_name, 'version': service_version,
                            'product': service_product
                        })
                    })
        except Exception as e:
            logger.error(f"❌ XML parse error: {e}")
        
        return findings

    def _severity_from_port(self, port):
        risky_ports = {
            '21': 'high', '23': 'critical', '25': 'medium',
            '135': 'high', '139': 'high', '445': 'critical',
            '1433': 'high', '3306': 'medium', '3389': 'high',
            '5432': 'medium', '6379': 'high', '27017': 'high',
        }
        return risky_ports.get(str(port), 'info')

    def ingest(self, xml_file):
        """Parse XML and store findings in DB"""
        findings = self.parse_xml(xml_file)
        logger.info(f"📊 Found {len(findings)} open ports")
        
        count = 0
        for finding in findings:
            try:
                query = """
                    INSERT INTO findings (finding_id, asset_id, source, title, description, severity, raw_data)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (finding_id) DO NOTHING
                """
                db.execute_query(query, (
                    finding['finding_id'], finding['asset_id'], finding['source'],
                    finding['title'], finding['description'], finding['severity'], finding['raw_data']
                ))
                count += 1
                logger.info(f"✅ Ingested: {finding['title']}")
            except Exception as e:
                logger.error(f"❌ Failed: {e}")
        
        return {'source': 'nmap', 'findings_ingested': count}

    def run(self, target='scanme.nmap.org'):
        xml_file = self.run_scan(target)
        if not xml_file:
            return {'source': 'nmap', 'error': 'scan_failed'}
        return self.ingest(xml_file)


if __name__ == "__main__":
    ingestor = NmapIngestor()
    result = ingestor.run('scanme.nmap.org')
    print(result)