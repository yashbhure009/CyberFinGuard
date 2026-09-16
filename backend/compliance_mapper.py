"""
Live Findings Compliance Mapper

Reads every row from the `findings` table, decides which five framework
controls it violates based on (source, title), and writes the tag list
back into findings.framework_tags.

Frameworks mapped:
  - ISO/IEC 27001
  - NIST Cybersecurity Framework (CSF)
  - CIS Controls v8
  - RBI Cyber Security Framework
  - SEBI CSCRF v1.0
"""

import os
import sys
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database import db

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

# ============================================================
# FRAMEWORK CONTROL FAMILIES
# ============================================================

FAMILY = {
    "injection":        ["ISO27001-A.14.2.5", "NIST-CSF-PR.DS-2", "CIS-4.1",  "RBI-3.2", "SEBI-2.1"],
    "input_validation": ["ISO27001-A.14.2.5", "NIST-CSF-PR.IP-1", "CIS-4.1",  "RBI-3.2", "SEBI-2.1"],
    "path_traversal":   ["ISO27001-A.13.1.1", "NIST-CSF-PR.AC-5", "CIS-9.1",  "RBI-5.1", "SEBI-3.2"],
    "memory_safety":    ["ISO27001-A.12.2.1", "NIST-CSF-DE.CM-3", "CIS-10.1", "RBI-6.1", "SEBI-4.1"],
    "auth":             ["ISO27001-A.9.4.2",  "NIST-CSF-PR.AC-7", "CIS-5.2",  "RBI-4.1", "SEBI-3.1"],
    "access_control":   ["ISO27001-A.9.2.3",  "NIST-CSF-PR.AC-4", "CIS-1.16", "RBI-4.2", "SEBI-3.1"],
    "info_exposure":    ["ISO27001-A.12.6",   "NIST-CSF-PR.DS-1", "CIS-3.3",  "RBI-5.2", "SEBI-3.3"],
    "crypto":           ["ISO27001-A.10.1.1", "NIST-CSF-PR.DS-2", "CIS-3.10", "RBI-5.2", "SEBI-3.3"],
    "resource":         ["ISO27001-A.12.2.1", "NIST-CSF-DE.CM-3", "CIS-10.1", "RBI-6.1", "SEBI-4.1"],
    "supply_chain":     ["ISO27001-A.12.6.1", "NIST-CSF-PR.DS-1", "CIS-3.3",  "RBI-5.2", "SEBI-3.3"],
    "cloud_config":     ["ISO27001-A.13.2.1", "NIST-CSF-PR.DS-1", "CIS-3.3",  "RBI-5.2", "SEBI-3.3"],
    "web_hardening":    ["ISO27001-A.14.2.5", "NIST-CSF-PR.IP-1", "CIS-4.1",  "RBI-3.2", "SEBI-2.1"],
    "iam":              ["ISO27001-A.9.4.2",  "NIST-CSF-PR.AC-7", "CIS-5.3",  "RBI-4.2", "SEBI-3.1"],
    "network":          ["ISO27001-A.13.1.1", "NIST-CSF-PR.AC-5", "CIS-9.1",  "RBI-5.1", "SEBI-3.2"],
}

FALLBACK_TAGS = ["ISO27001-A.12.6", "NIST-CSF-ID.RA-1", "CIS-1.1", "RBI-5.1", "SEBI-3.2"]


# ============================================================
# (source, keyword) -> family
# ============================================================

RULES = {
    # ---- ZAP ----
    ("zap", "cross site"):        "injection",
    ("zap", "xss"):               "injection",
    ("zap", "sql"):               "injection",
    ("zap", "csrf"):              "injection",
    ("zap", "anti-csrf"):         "injection",
    ("zap", "header"):            "web_hardening",
    ("zap", "clickjacking"):      "web_hardening",
    ("zap", "csp"):               "web_hardening",
    ("zap", "content security"):  "web_hardening",
    ("zap", "cross-domain"):      "web_hardening",
    ("zap", "cors"):              "web_hardening",
    ("zap", "server leaks"):      "info_exposure",
    ("zap", "cache-control"):     "info_exposure",
    ("zap", "information disclosure"): "info_exposure",
    ("zap", "suspicious comment"):"info_exposure",
    ("zap", "vulnerable js"):     "supply_chain",
    ("zap", "sub resource"):      "web_hardening",
    ("zap", "authentication"):    "auth",

    # ---- Nmap ----
    ("nmap", "open port"):        "network",

    # ---- Nuclei ----
    ("nuclei", "xss"):            "injection",
    ("nuclei", "cross-site"):     "injection",
    ("nuclei", "open redirect"):  "injection",
    ("nuclei", "sql"):            "injection",
    ("nuclei", "rce"):            "injection",
    ("nuclei", "command"):        "injection",

    # ---- Wazuh ----
    ("wazuh", "ssh"):             "auth",
    ("wazuh", "login"):           "auth",
    ("wazuh", "malware"):         "memory_safety",
    ("wazuh", "auth"):            "auth",

    # ---- Prowler ----
    ("prowler", "s3"):            "cloud_config",
    ("prowler", "bucket"):        "cloud_config",
    ("prowler", "iam"):           "iam",
    ("prowler", "public"):        "cloud_config",

    # ---- Keycloak ----
    ("keycloak", "mfa"):          "iam",
    ("keycloak", "user"):         "iam",
    ("keycloak", "role"):         "iam",
    ("keycloak", "authentication"):"iam",

    # ---- OpenVAS (sample data) ----
    ("openvas", "remote code"):   "injection",
    ("openvas", "sql injection"): "injection",
    ("openvas", "cross-site"):    "injection",
    ("openvas", "xss"):           "injection",
}


def pick_family(source, title):
    """Return the family for a given (source, title)."""
    src = (source or "").lower()
    t = (title or "").lower()
    for (s, keyword), family in RULES.items():
        if s == src and keyword in t:
            return family
    return None


def get_tags(source, title):
    family = pick_family(source, title)
    if family:
        return FAMILY[family]
    return FALLBACK_TAGS


# ============================================================
# MAPPER
# ============================================================

class ComplianceMapper:
    def __init__(self):
        self.stats = {
            "total": 0,
            "mapped": 0,
            "fallback_used": 0,
            "by_source": {},
            "by_framework": {
                "ISO27001": 0, "NIST-CSF": 0, "CIS": 0, "RBI": 0, "SEBI": 0,
            },
        }

    def fetch_findings(self):
        return db.execute_query(
            "SELECT finding_id, source, title FROM findings ORDER BY created_at DESC"
        )

    def update_tags(self, finding_id, tags):
        db.execute_query(
            "UPDATE findings SET framework_tags = %s WHERE finding_id = %s",
            (tags, finding_id),
        )

    def run(self):
        logger.info("=" * 60)
        logger.info("Starting Compliance Mapping")
        logger.info("=" * 60)

        findings = self.fetch_findings()
        self.stats["total"] = len(findings)
        logger.info(f"Fetched {len(findings)} findings from database")

        if not findings:
            logger.warning("No findings to map")
            return self.stats

        for row in findings:
            fid = row["finding_id"]
            source = row.get("source") or "default"
            title = row.get("title") or ""

            tags = get_tags(source, title)
            if tags == FALLBACK_TAGS:
                self.stats["fallback_used"] += 1

            try:
                self.update_tags(fid, tags)
                self.stats["mapped"] += 1
                self.stats["by_source"][source] = self.stats["by_source"].get(source, 0) + 1

                for tag in tags:
                    for fw in self.stats["by_framework"]:
                        if tag.startswith(fw):
                            self.stats["by_framework"][fw] += 1
                            break

                logger.info(f"Mapped {fid} [{source}] -> {tags}")
            except Exception as e:
                logger.error(f"Failed to map {fid}: {e}")

        logger.info("=" * 60)
        logger.info("COMPLIANCE MAPPING SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Total:          {self.stats['total']}")
        logger.info(f"Mapped:         {self.stats['mapped']}")
        logger.info(f"Fallback used:  {self.stats['fallback_used']}")
        logger.info("By source:")
        for s, c in self.stats["by_source"].items():
            logger.info(f"  {s}: {c}")
        logger.info("By framework:")
        for f, c in self.stats["by_framework"].items():
            logger.info(f"  {f}: {c}")

        return self.stats


if __name__ == "__main__":
    mapper = ComplianceMapper()
    stats = mapper.run()
    print(f"\nDone: {stats['mapped']}/{stats['total']} findings mapped")
    print(f"Fallback used: {stats['fallback_used']}")
