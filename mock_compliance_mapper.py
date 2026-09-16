"""
Mock Compliance Mapper
Reads mock_findings_enriched, maps each CWE to five framework controls,
writes framework_tags back to mock_findings.

Handles:
  - Single CWE:   'CWE-79'
  - Multi CWE:    'CWE-79, CWE-80'
  - Blank CWE:    ''  ->  generic fallback tags
"""

import os
import logging
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
logger = logging.getLogger(__name__)

DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "localhost"),
    "database": os.getenv("DB_NAME", "cyber_risk_db"),
    "user":     os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "postgres"),
    "port":     os.getenv("DB_PORT", "5432"),
}

# ============================================================
# FRAMEWORK CONTROL FAMILIES
# Reused across many CWEs so we never invent new tags
# ============================================================

FAMILY = {
    "injection":      ["ISO27001-A.14.2.5", "NIST-CSF-PR.DS-2", "CIS-4.1",  "RBI-3.2", "SEBI-2.1"],
    "input_validation":["ISO27001-A.14.2.5", "NIST-CSF-PR.IP-1", "CIS-4.1",  "RBI-3.2", "SEBI-2.1"],
    "path_traversal": ["ISO27001-A.13.1.1", "NIST-CSF-PR.AC-5", "CIS-9.1",  "RBI-5.1", "SEBI-3.2"],
    "memory_safety":  ["ISO27001-A.12.2.1", "NIST-CSF-DE.CM-3", "CIS-10.1", "RBI-6.1", "SEBI-4.1"],
    "auth":           ["ISO27001-A.9.4.2",  "NIST-CSF-PR.AC-7", "CIS-5.2",  "RBI-4.1", "SEBI-3.1"],
    "access_control": ["ISO27001-A.9.2.3",  "NIST-CSF-PR.AC-4", "CIS-1.16", "RBI-4.2", "SEBI-3.1"],
    "info_exposure":  ["ISO27001-A.12.6",   "NIST-CSF-PR.DS-1", "CIS-3.3",  "RBI-5.2", "SEBI-3.3"],
    "crypto":         ["ISO27001-A.10.1.1", "NIST-CSF-PR.DS-2", "CIS-3.10", "RBI-5.2", "SEBI-3.3"],
    "resource":       ["ISO27001-A.12.2.1", "NIST-CSF-DE.CM-3", "CIS-10.1", "RBI-6.1", "SEBI-4.1"],
    "supply_chain":   ["ISO27001-A.12.6.1", "NIST-CSF-PR.DS-1", "CIS-3.3",  "RBI-5.2", "SEBI-3.3"],
    "race":           ["ISO27001-A.12.2.1", "NIST-CSF-DE.CM-3", "CIS-10.1", "RBI-6.1", "SEBI-4.1"],
}

# ============================================================
# CWE -> FAMILY
# ============================================================

CWE_TO_FAMILY = {
    # Injection
    "CWE-74":  "injection",
    "CWE-77":  "injection",
    "CWE-78":  "injection",
    "CWE-79":  "injection",
    "CWE-80":  "injection",
    "CWE-89":  "injection",
    "CWE-94":  "injection",
    "CWE-134": "injection",
    "CWE-150": "injection",
    "CWE-444": "injection",
    "CWE-1336":"injection",
    "CWE-88":  "injection",

    # Input validation
    "CWE-17":  "input_validation",
    "CWE-20":  "input_validation",
    "CWE-184": "input_validation",
    "CWE-697": "input_validation",

    # Path traversal
    "CWE-22":  "path_traversal",
    "CWE-23":  "path_traversal",
    "CWE-29":  "path_traversal",
    "CWE-59":  "path_traversal",
    "CWE-552": "path_traversal",

    # Memory safety
    "CWE-119": "memory_safety",
    "CWE-120": "memory_safety",
    "CWE-121": "memory_safety",
    "CWE-122": "memory_safety",
    "CWE-123": "memory_safety",
    "CWE-125": "memory_safety",
    "CWE-130": "memory_safety",
    "CWE-190": "memory_safety",
    "CWE-369": "memory_safety",
    "CWE-401": "memory_safety",
    "CWE-416": "memory_safety",
    "CWE-459": "memory_safety",
    "CWE-476": "memory_safety",
    "CWE-617": "memory_safety",
    "CWE-772": "memory_safety",
    "CWE-787": "memory_safety",
    "CWE-824": "memory_safety",
    "CWE-908": "memory_safety",

    # Auth
    "CWE-287": "auth",
    "CWE-288": "auth",
    "CWE-306": "auth",
    "CWE-307": "auth",
    "CWE-522": "auth",
    "CWE-798": "auth",
    "CWE-799": "auth",
    "CWE-940": "auth",

    # Access control
    "CWE-264": "access_control",
    "CWE-266": "access_control",
    "CWE-269": "access_control",
    "CWE-284": "access_control",
    "CWE-285": "access_control",
    "CWE-425": "access_control",
    "CWE-639": "access_control",
    "CWE-732": "access_control",
    "CWE-862": "access_control",
    "CWE-863": "access_control",

    # Info exposure
    "CWE-200": "info_exposure",
    "CWE-203": "info_exposure",
    "CWE-204": "info_exposure",
    "CWE-598": "info_exposure",
    "CWE-611": "info_exposure",

    # Crypto
    "CWE-319": "crypto",
    "CWE-327": "crypto",

    # Resource
    "CWE-400": "resource",
    "CWE-404": "resource",
    "CWE-770": "resource",
    "CWE-835": "resource",
    "CWE-1333":"resource",

    # Supply chain
    "CWE-434": "supply_chain",
    "CWE-494": "supply_chain",
    "CWE-502": "memory_safety",   # deserialization -> treat as memory
    "CWE-73":  "supply_chain",

    # Race
    "CWE-367": "race",

    # Web behavioural
    "CWE-352": "injection",       # CSRF
    "CWE-601": "injection",       # open redirect
    "CWE-693": "input_validation",
    "CWE-918": "path_traversal",  # SSRF
}

FALLBACK_TAGS = ["ISO27001-A.12.6", "NIST-CSF-ID.RA-1", "CIS-1.1", "RBI-5.1", "SEBI-3.2"]


def _normalise_cwe(cwe_string):
    """Split 'CWE-125, CWE-20' or 'CWE-74,CWE-77' into ['CWE-125','CWE-20']."""
    if not cwe_string:
        return []
    parts = str(cwe_string).replace(",", " ").split()
    return [p.strip().upper() for p in parts if p.strip().upper().startswith("CWE-")]


def get_tags(cwe_id):
    """
    Return the five-framework tag list for a CWE string.
    Uses the first recognised CWE in the string.
    Falls back to FALLBACK_TAGS if nothing matches.
    """
    cwes = _normalise_cwe(cwe_id)
    if not cwes:
        return FALLBACK_TAGS

    for c in cwes:
        family = CWE_TO_FAMILY.get(c)
        if family:
            return FAMILY[family]

    return FALLBACK_TAGS


def main():
    print("=" * 60)
    print("Mock Compliance Mapper")
    print("=" * 60)

    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor(cursor_factory=RealDictCursor)

    cur.execute("SELECT finding_id, cwe_id FROM mock_findings_enriched ORDER BY finding_id")
    rows = cur.fetchall()
    print(f"Fetched {len(rows)} mock findings from enriched view")

    if not rows:
        print("Nothing to map. Exiting.")
        return

    mapped_rows = []
    stats_by_framework = {"ISO27001": 0, "NIST-CSF": 0, "CIS": 0, "RBI": 0, "SEBI": 0}
    unmapped = 0
    fallback_used = 0
    unmatched_cwes = set()

    for row in rows:
        tags = get_tags(row["cwe_id"])

        if not row["cwe_id"] or str(row["cwe_id"]).strip() == "":
            unmapped += 1

        if tags == FALLBACK_TAGS:
            fallback_used += 1
            # Record which CWEs actually fell through
            for c in _normalise_cwe(row["cwe_id"]):
                if c not in CWE_TO_FAMILY:
                    unmatched_cwes.add(c)

        mapped_rows.append((tags, row["finding_id"]))

        for tag in tags:
            for fw in stats_by_framework:
                if tag.startswith(fw):
                    stats_by_framework[fw] += 1
                    break

    print(f"Built tag lists for {len(mapped_rows)} rows")
    print(f"Rows with blank CWE (source data gap):  {unmapped}")
    print(f"Rows that used the generic fallback:    {fallback_used}")

    if unmatched_cwes:
        print(f"Unmatched CWEs still present: {sorted(unmatched_cwes)}")
    else:
        print("Unmatched CWEs still present: none")

    update_sql = """
        UPDATE mock_findings AS m
        SET framework_tags = v.tags
        FROM (VALUES %s) AS v(tags, finding_id)
        WHERE m.finding_id = v.finding_id
    """

    execute_values(
        cur,
        update_sql,
        mapped_rows,
        template="(%s::text[], %s)",
        page_size=500,
    )
    conn.commit()

    cur.execute("SELECT COUNT(*) AS c FROM mock_findings WHERE framework_tags IS NOT NULL")
    tagged_count = cur.fetchone()["c"]

    print("=" * 60)
    print(f"Rows with framework_tags set: {tagged_count}")
    print("Tag counts by framework:")
    for fw, count in stats_by_framework.items():
        print(f"  {fw}: {count}")
    print("=" * 60)

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
