"""
Load mock_findings_10000.csv into PostgreSQL as the mock_findings table.
Run once. Safe to re-run — uses ON CONFLICT DO NOTHING on finding_id.
"""

import os
import sys
import pandas as pd
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

load_dotenv()

CSV_PATH = "/Users/yash/Downloads/mock_findings_10000.csv"

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "database": os.getenv("DB_NAME", "cyber_risk_db"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "postgres"),
    "port": os.getenv("DB_PORT", "5432"),
}

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS mock_findings (
    finding_id           VARCHAR(30) PRIMARY KEY,
    asset_name           VARCHAR(200),
    asset_criticality    INTEGER,
    business_value_inr   BIGINT,
    cve_id               VARCHAR(30),
    cvss_score           DECIMAL(3,1),
    epss_score           DECIMAL(6,5),
    cisa_kev             BOOLEAN,
    exploit_available    BOOLEAN,
    exploit_type         VARCHAR(30),
    threat_actor         VARCHAR(60),
    malware              BOOLEAN,
    mitre_technique      VARCHAR(20),
    patched              BOOLEAN,
    mfa                  BOOLEAN,
    waf                  BOOLEAN,
    edr                  BOOLEAN,
    incident             INTEGER,
    framework_tags       TEXT[],
    loaded_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_mock_findings_cve     ON mock_findings(cve_id);
CREATE INDEX IF NOT EXISTS idx_mock_findings_asset   ON mock_findings(asset_name);
CREATE INDEX IF NOT EXISTS idx_mock_findings_kev     ON mock_findings(cisa_kev);
CREATE INDEX IF NOT EXISTS idx_mock_findings_incid   ON mock_findings(incident);
"""


def to_bool(value):
    if value is None:
        return None
    s = str(value).strip().lower()
    if s in ("yes", "true", "1", "y"):
        return True
    if s in ("no", "false", "0", "n", ""):
        return False
    return None


def to_float(value):
    try:
        if value is None or str(value).strip() == "":
            return None
        return float(value)
    except (ValueError, TypeError):
        return None


def to_int(value):
    try:
        if value is None or str(value).strip() == "":
            return None
        return int(float(value))
    except (ValueError, TypeError):
        return None


def to_str(value, limit):
    if value is None:
        return None
    s = str(value).strip()
    if s == "":
        return None
    return s[:limit]


def main():
    print("=" * 60)
    print("Loading mock_findings from CSV")
    print("=" * 60)

    if not os.path.exists(CSV_PATH):
        print(f"CSV not found at {CSV_PATH}")
        sys.exit(1)

    df = pd.read_csv(CSV_PATH, dtype=str, keep_default_na=False)
    print(f"Read {len(df)} rows from CSV")

    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    cur.execute(CREATE_TABLE_SQL)
    conn.commit()
    print("mock_findings table is ready")

    rows = []
    skipped = 0
    for _, r in df.iterrows():
        fid = (r.get("finding_id") or "").strip()
        if not fid:
            skipped += 1
            continue

        rows.append((
            fid[:30],
            to_str(r.get("asset_name"), 200),
            to_int(r.get("asset_criticality")),
            to_int(r.get("business_value_inr")),
            to_str(r.get("cve_id"), 30),
            to_float(r.get("cvss_score")),
            to_float(r.get("epss_score")),
            to_bool(r.get("cisa_kev")),
            to_bool(r.get("exploit_available")),
            to_str(r.get("exploit_type"), 30),
            to_str(r.get("threat_actor"), 60),
            to_bool(r.get("malware")),
            to_str(r.get("mitre_technique"), 20),
            to_bool(r.get("patched")),
            to_bool(r.get("mfa")),
            to_bool(r.get("waf")),
            to_bool(r.get("edr")),
            to_int(r.get("incident")),
        ))

    print(f"Prepared {len(rows)} rows for insert (skipped {skipped})")

    insert_sql = """
        INSERT INTO mock_findings (
            finding_id, asset_name, asset_criticality, business_value_inr,
            cve_id, cvss_score, epss_score, cisa_kev, exploit_available,
            exploit_type, threat_actor, malware, mitre_technique,
            patched, mfa, waf, edr, incident
        ) VALUES %s
        ON CONFLICT (finding_id) DO NOTHING
    """

    execute_values(cur, insert_sql, rows, page_size=500)
    conn.commit()

    cur.execute("SELECT COUNT(*) FROM mock_findings")
    total = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM mock_findings WHERE incident = 1")
    incident_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(*) FROM mock_findings WHERE cisa_kev = TRUE")
    kev_count = cur.fetchone()[0]
    cur.execute("SELECT COUNT(DISTINCT cve_id) FROM mock_findings WHERE cve_id IS NOT NULL")
    cve_count = cur.fetchone()[0]

    print("=" * 60)
    print(f"Total rows in mock_findings: {total}")
    print(f"Rows with incident = 1:      {incident_count}")
    print(f"Rows with cisa_kev = TRUE:   {kev_count}")
    print(f"Distinct CVEs referenced:    {cve_count}")
    print("=" * 60)

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
