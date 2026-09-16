"""
Compliance Mapper
Reads findings from PostgreSQL, maps them to 5 frameworks,
and writes framework_tags back to the same row.

Frameworks:
  - ISO/IEC 27001
  - NIST Cybersecurity Framework (CSF)
  - CIS Controls
  - RBI Cyber Security Framework
  - SEBI CSCRF v1.0
"""

import os
import sys
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database import db

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


FRAMEWORK_RULES = {
    'zap': {
        'xss':     ['ISO27001-A.14.2.5', 'NIST-CSF-PR.DS-2', 'CIS-4.1',  'RBI-3.2', 'SEBI-2.1'],
        'sql':     ['ISO27001-A.14.2.5', 'NIST-CSF-PR.DS-2', 'CIS-4.1',  'RBI-3.2', 'SEBI-2.1'],
        'csrf':    ['ISO27001-A.14.2.5', 'NIST-CSF-PR.DS-2', 'CIS-4.1',  'RBI-3.2', 'SEBI-2.1'],
        'header':  ['ISO27001-A.14.2.5', 'NIST-CSF-PR.IP-1', 'CIS-4.1',  'RBI-3.2', 'SEBI-2.1'],
        'default': ['ISO27001-A.12.6',   'NIST-CSF-ID.RA-1', 'CIS-1.1',  'RBI-5.1', 'SEBI-3.2'],
    },
    'nmap': {
        'default': ['ISO27001-A.13.1.1', 'NIST-CSF-PR.AC-5', 'CIS-9.1',  'RBI-5.1', 'SEBI-3.2'],
    },
    'nuclei': {
        'default': ['ISO27001-A.12.6.1', 'NIST-CSF-ID.RA-2', 'CIS-7.1',  'RBI-5.3', 'SEBI-3.4'],
    },
    'wazuh': {
        'login':   ['ISO27001-A.9.4.2',  'NIST-CSF-PR.AC-7', 'CIS-5.2',  'RBI-4.1', 'SEBI-3.1'],
        'malware': ['ISO27001-A.12.2.1', 'NIST-CSF-DE.CM-3', 'CIS-10.1', 'RBI-6.1', 'SEBI-4.1'],
        'default': ['ISO27001-A.12.4.1', 'NIST-CSF-DE.AE-2', 'CIS-6.1',  'RBI-4.2', 'SEBI-3.2'],
    },
    'prowler': {
        's3':      ['ISO27001-A.13.2.1', 'NIST-CSF-PR.DS-1', 'CIS-3.3',  'RBI-5.2', 'SEBI-3.3'],
        'iam':     ['ISO27001-A.9.2.3',  'NIST-CSF-PR.AC-4', 'CIS-1.16', 'RBI-4.2', 'SEBI-3.1'],
        'default': ['ISO27001-A.12.6',   'NIST-CSF-PR.IP-1', 'CIS-1.1',  'RBI-5.1', 'SEBI-3.2'],
    },
    'keycloak': {
        'mfa':     ['ISO27001-A.9.4.2', 'NIST-CSF-PR.AC-7', 'CIS-5.3',  'RBI-4.2', 'SEBI-3.1'],
        'default': ['ISO27001-A.9.2.1', 'NIST-CSF-PR.AC-1', 'CIS-5.1',  'RBI-4.1', 'SEBI-3.1'],
    },
    'default': ['ISO27001-A.12.6', 'NIST-CSF-ID.RA-1', 'CIS-1.1', 'RBI-5.1', 'SEBI-3.2'],
}


class ComplianceMapper:
    def __init__(self):
        self.stats = {
            'total': 0,
            'mapped': 0,
            'by_source': {},
            'by_framework': {'ISO27001': 0, 'NIST-CSF': 0, 'CIS': 0, 'RBI': 0, 'SEBI': 0},
        }

    def get_tags(self, source, title):
        rules = FRAMEWORK_RULES.get(source, FRAMEWORK_RULES['default'])
        t = (title or '').lower()

        if 'xss' in t or 'cross site' in t:
            return rules.get('xss', rules['default'])
        if 'sql' in t:
            return rules.get('sql', rules['default'])
        if 'csrf' in t:
            return rules.get('csrf', rules['default'])
        if 'header' in t:
            return rules.get('header', rules['default'])
        if 'login' in t or 'ssh' in t:
            return rules.get('login', rules['default'])
        if 'malware' in t:
            return rules.get('malware', rules['default'])
        if 's3' in t or 'bucket' in t:
            return rules.get('s3', rules['default'])
        if 'mfa' in t:
            return rules.get('mfa', rules['default'])

        return rules['default']

    def fetch_findings(self):
        return db.execute_query(
            "SELECT finding_id, source, title FROM findings ORDER BY created_at DESC"
        )

    def update_tags(self, finding_id, tags):
        db.execute_query(
            "UPDATE findings SET framework_tags = %s WHERE finding_id = %s",
            (tags, finding_id)
        )

    def run(self):
        logger.info("=" * 60)
        logger.info("Starting Compliance Mapping")
        logger.info("=" * 60)

        findings = self.fetch_findings()
        self.stats['total'] = len(findings)
        logger.info(f"Fetched {len(findings)} findings from database")

        if not findings:
            logger.warning("No findings to map")
            return self.stats

        for row in findings:
            fid = row['finding_id']
            source = row.get('source') or 'default'
            title = row.get('title') or ''

            tags = self.get_tags(source, title)

            try:
                self.update_tags(fid, tags)
                self.stats['mapped'] += 1
                self.stats['by_source'][source] = self.stats['by_source'].get(source, 0) + 1

                for tag in tags:
                    for fw in self.stats['by_framework']:
                        prefix = fw.replace('-CSF', '')
                        if tag.startswith(prefix):
                            self.stats['by_framework'][fw] += 1
                            break

                logger.info(f"Mapped {fid} [{source}] -> {tags}")
            except Exception as e:
                logger.error(f"Failed to map {fid}: {e}")

        logger.info("=" * 60)
        logger.info("COMPLIANCE MAPPING SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total:  {self.stats['total']}")
        logger.info(f"Mapped: {self.stats['mapped']}")
        logger.info("By source:")
        for s, c in self.stats['by_source'].items():
            logger.info(f"  {s}: {c}")
        logger.info("By framework (tag count):")
        for f, c in self.stats['by_framework'].items():
            logger.info(f"  {f}: {c}")

        return self.stats


if __name__ == "__main__":
    mapper = ComplianceMapper()
    stats = mapper.run()
    print(f"\nDone: {stats['mapped']}/{stats['total']} findings mapped")
