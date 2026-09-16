"""
Load cve_300_enriched.csv into PostgreSQL as the cve_intel lookup table.
Run this once. Safe to re-run — it uses ON CONFLICT DO NOTHING.
"""

import os
import sys
import pandas as pd
import psycopg2
from psycopg2.extras import execute_values
from dotenv import load_dotenv

load_dotenv()

CSV_PATH = "/Users/yash/Downloads/cve_300_enriched.csv"

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "database": os.getenv("DB_NAME", "cyber_risk_db"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "postgres"),
    "port": os.getenv("DB_PORT", "5432"),
}

CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS cve_intel (
    cve_id              VARCHAR(30) PRIMARY KEY,
    description         TEXT,
    affected_vendor     TEXT,
    affected_product    TEXT,
    technology          VARCHAR(80),
    cwe_id              TEXT,
    cvss_score          DECIMAL(3,1),
    cvss_version        VARCHAR(10),
    cvss_vector         TEXT,
    epss_score          DECIMAL(6,5),
    epss_percentile     DECIMAL(6,5),
    cisa_kev            BOOLEAN,
    exploit_available   BOOLEAN,
    published_date      TIMESTAMP,
    published_year      INTEGER,
    severity            VARCHAR(20),
    selection_score     DECIMAL(8,6),
    raw_data            JSONB,
    loaded_at           TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_cve_intel_cwe  ON cve_intel(cwe_id);
CREATE INDEX IF NOT EXISTS idx_cve_intel_kev  ON cve_intel(cisa_kev);
CREATE INDEX IF NOT EXISTS idx_cve_intel_sev  ON cve_intel(severity);
"""


def to_bool(value):
    """Convert Yes/No/True/False strings to python bool or None."""
    if value is None:
        return None
    s = str(value).strip().lower()
    if s in ("yes", "true", "1", "y"):
        return True
    if s in ("no", "false", "0", "n"):
        return False
    return None


def clean_float(value):
    """Return float or None."""
    try:
        if value is None or str(value).strip() == "":
            return None
        return float(value)
    except (ValueError, TypeError):
        return None


def clean_int(value):
    """Return int or None."""
    try:
        if value is None or str(value).strip() == "":
            return None
        return int(float(value))
    except (ValueError, TypeError):
        return None


def clean_timestamp(value):
    """Return a string suitable for Postgres timestamp or None."""
    if value is None or str(value).strip() == "":
        return None
    try:
        return pd.to_datetime(value).to_pydatetime()
    except Exception:
        return None


def main():
    print("=" * 60)
    print("Loading cve_intel from CSV")
    print("=" * 60)

    if not os.path.exists(CSV_PATH):
        print(f"CSV not found at {CSV_PATH}")
        sys.exit(1)

    df = pd.read_csv(CSV_PATH, dtype=str, keep_default_na=False)
    print(f"Read {len(df)} rows from CSV")
    print(f"Columns: {list(df.columns)}")

    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()

    cur.execute(CREATE_TABLE_SQL)
    conn.commit()
    print("cve_intel table is ready")

    rows = []
    for _, r in df.iterrows():
        cve_id = (r.get("cve_id") or "").strip()
        if not cve_id:
            continue

        rows.append((
            cve_id[:30],
            (r.get("description") or "")[:10000],
            (r.get("affected_vendor") or "")[:2000],
            (r.get("affected_product") or "")[:2000],
            (r.get("technology") or "")[:80],
            (r.get("cwe_id") or "")[:500],
            clean_float(r.get("cvss_score")),
            (r.get("cvss_version") or "")[:10],
            (r.get("cvss_vector") or "")[:500],
            clean_float(r.get("epss_score")),
            clean_float(r.get("epss_percentile")),
            to_bool(r.get("cisa_kev")),
            to_bool(r.get("exploit_available")),
            clean_timestamp(r.get("published_date")),
            clean_int(r.get("published_year")),
            (r.get("severity") or "")[:20],
            clean_float(r.get("selection_score")),
            r.to_json(),          # raw_data JSONB
        ))

    print(f"Prepared {len(rows)} rows for insert")

    insert_sql = """
        INSERT INTO cve_intel (
            cve_id, description, affected_vendor, affected_product,
            technology, cwe_id, cvss_score, cvss_version, cvss_vector,
            epss_score, epss_percentile, cisa_kev, exploit_available,
            published_date, published_year, severity, selection_score,
            raw_data
        ) VALUES %s
        ON CONFLICT (cve_id) DO NOTHING
    """

    execute_values(cur, insert_sql, rows, page_size=100)
    conn.commit()

    cur.execute("SELECT COUNT(*) FROM cve_intel")
    total = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM cve_intel WHERE cisa_kev = TRUE")
    kev_count = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM cve_intel WHERE severity = 'Critical'")
    crit_count = cur.fetchone()[0]

    print("=" * 60)
    print(f"Total rows in cve_intel: {total}")
    print(f"CISA KEV flagged:        {kev_count}")
    print(f"Critical severity:       {crit_count}")
    print("=" * 60)

    cur.close()
    conn.close()


if __name__ == "__main__":
    main()
