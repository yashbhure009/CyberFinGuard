"""
CyberFinGuard - Prowler PostgreSQL Loader

Loads the latest normalized Prowler CSV into:
    assets
    findings

Important:
- Prowler RESOURCE_UID can be longer than the DB asset_id limit.
  We therefore generate a deterministic short asset_id.
- Prowler FINDING_UID can be longer than the DB finding_id limit.
  We therefore generate a deterministic short finding_id.
- The original Prowler identifiers are preserved inside raw_data.
- pandas NaN/NaT values are converted to JSON-safe None.
"""

import os
import json
import math
import hashlib
import glob
import logging

import pandas as pd
import psycopg2
from psycopg2.extras import Json
from dotenv import load_dotenv


# ============================================================
# Configuration
# ============================================================

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

logger = logging.getLogger(__name__)


PROJECT_ROOT = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "..",
        ".."
    )
)

PROWLER_RESULTS_DIR = os.path.join(
    os.path.dirname(__file__),
    "prowler_results"
)


# ============================================================
# Database configuration
# ============================================================

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "database": os.getenv("DB_NAME", "cyber_risk_db"),
    "user": os.getenv("DB_USER", "postgres"),
    "password": os.getenv("DB_PASSWORD", "postgres"),
    "port": os.getenv("DB_PORT", "5432"),
}


# ============================================================
# Utility functions
# ============================================================

def make_json_safe(value):
    """
    Convert pandas/numpy values into valid JSON-compatible
    Python values.

    Important:
    pandas uses NaN for missing values.
    JSON does NOT allow NaN.
    PostgreSQL JSONB therefore rejects it.
    """

    if value is None:
        return None

    # Handle pandas NaN / NaT / missing values
    try:
        if pd.isna(value):
            return None
    except (TypeError, ValueError):
        pass

    # Convert numpy scalar -> native Python scalar
    if hasattr(value, "item"):
        try:
            value = value.item()
        except (TypeError, ValueError):
            pass

    # JSON does not allow NaN or Infinity
    if isinstance(value, float):
        if not math.isfinite(value):
            return None

    return value


def make_raw_data(row):
    """
    Convert the complete pandas row into JSON-safe data.
    """

    raw_data = {}

    for key, value in row.to_dict().items():
        raw_data[str(key)] = make_json_safe(value)

    return raw_data


def generate_asset_id(resource_uid):
    """
    Generate a deterministic CyberFinGuard asset ID.

    Example:
        arn:aws:iam::012092091624:root
        ->
        aws_78ca40ff6af6627b
    """

    resource_uid = str(resource_uid).strip()

    if not resource_uid:
        resource_uid = "unknown-resource"

    digest = hashlib.sha256(
        resource_uid.encode("utf-8")
    ).hexdigest()[:16]

    return f"aws_{digest}"


def generate_finding_id(prowler_finding_id):
    """
    Generate a deterministic short DB finding ID.

    Prowler FINDING_UID can be much longer than VARCHAR(50).
    """

    prowler_finding_id = str(
        prowler_finding_id
    ).strip()

    if not prowler_finding_id:
        prowler_finding_id = "unknown-finding"

    digest = hashlib.sha256(
        prowler_finding_id.encode("utf-8")
    ).hexdigest()[:16]

    return f"pwl_{digest}"


def clean_string(value):
    """
    Convert a value into a clean string or None.
    """

    value = make_json_safe(value)

    if value is None:
        return None

    return str(value).strip()


def clean_float(value):
    """
    Convert a value to float or None.
    """

    value = make_json_safe(value)

    if value is None:
        return None

    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def clean_bool(value):
    """
    Convert common boolean representations into Python bool.
    """

    value = make_json_safe(value)

    if value is None:
        return None

    if isinstance(value, bool):
        return value

    value_str = str(value).strip().lower()

    if value_str in {
        "true",
        "yes",
        "y",
        "1"
    }:
        return True

    if value_str in {
        "false",
        "no",
        "n",
        "0"
    }:
        return False

    return None


# ============================================================
# Find latest normalized Prowler file
# ============================================================

def find_latest_normalized_file():
    """
    Find the newest *_normalized.csv file.
    """

    pattern = os.path.join(
        PROWLER_RESULTS_DIR,
        "*_normalized.csv"
    )

    files = glob.glob(pattern)

    if not files:
        raise FileNotFoundError(
            f"No normalized Prowler CSV found in:\n"
            f"{PROWLER_RESULTS_DIR}"
        )

    latest_file = max(
        files,
        key=os.path.getmtime
    )

    return latest_file


# ============================================================
# Database connection
# ============================================================

def connect_database():
    """
    Connect to PostgreSQL using .env configuration.
    """

    logger.info(
        "Connecting to PostgreSQL at %s:%s",
        DB_CONFIG["host"],
        DB_CONFIG["port"]
    )

    conn = psycopg2.connect(
        host=DB_CONFIG["host"],
        database=DB_CONFIG["database"],
        user=DB_CONFIG["user"],
        password=DB_CONFIG["password"],
        port=DB_CONFIG["port"]
    )

    conn.autocommit = False

    logger.info("Database connection successful.")

    return conn


# ============================================================
# Asset UPSERT
# ============================================================

def upsert_asset(cursor, row, asset_id):
    """
    Insert or update an AWS resource in the assets table.

    We intentionally do NOT invent:
        criticality
        asset_value
        business_unit
        owner

    Those should come from CyberFinGuard business context later.
    """

    resource_uid = clean_string(
        row.get("resource_uid")
    )

    asset_name = clean_string(
        row.get("asset_name")
    )

    if not asset_name:
        asset_name = resource_uid or asset_id

    region = clean_string(
        row.get("region")
    )

    # Preserve useful source information.
    resource_details = {
        "source": "prowler",
        "resource_uid": resource_uid,
        "region": region,
    }

    cursor.execute(
        """
        INSERT INTO assets (
            asset_id,
            asset_name,
            asset_type,
            application,
            environment,
            criticality,
            discovered_at,
            updated_at
        )
        VALUES (
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
        )
        ON CONFLICT (asset_id)
        DO UPDATE SET
            asset_name = EXCLUDED.asset_name,
            asset_type = EXCLUDED.asset_type,
            application = EXCLUDED.application,
            updated_at = CURRENT_TIMESTAMP
        """,
        (
            asset_id,
            asset_name,
            "AWS",
            "Prowler",
            "unknown",
            None,
        )
    )


# ============================================================
# Finding UPSERT
# ============================================================

def upsert_finding(
    cursor,
    row,
    asset_id
):
    """
    Insert or update a Prowler finding.
    """

    original_finding_id = clean_string(
        row.get("finding_id")
    )

    db_finding_id = generate_finding_id(
        original_finding_id
    )

    resource_uid = clean_string(
        row.get("resource_uid")
    )

    title = clean_string(
        row.get("title")
    )

    description = clean_string(
        row.get("description")
    )

    severity = clean_string(
        row.get("severity")
    )

    if severity:
        severity = severity.lower()

    # Make sure severity matches the DB CHECK constraint.
    allowed_severities = {
        "critical",
        "high",
        "medium",
        "low",
        "info"
    }

    if severity not in allowed_severities:
        severity = "info"

    # --------------------------------------------------------
    # CVE / CVSS / EPSS
    # --------------------------------------------------------
    #
    # Prowler IAM configuration findings are not CVE findings.
    # Do NOT fabricate vulnerability values.
    #

    cve_id = clean_string(
        row.get("cve_id")
    )

    cvss_score = clean_float(
        row.get("cvss_score")
    )

    epss_score = clean_float(
        row.get("epss_score")
    )

    exploit_available = clean_bool(
        row.get("exploit_available")
    )

    # --------------------------------------------------------
    # Raw Prowler data
    # --------------------------------------------------------

    raw_data = make_raw_data(row)

    # Add CyberFinGuard integration metadata.
    raw_data["cyberfinguard"] = {
        "original_prowler_finding_id":
            original_finding_id,

        "resource_uid":
            resource_uid,

        "asset_id":
            asset_id,

        "control_status":
            clean_string(
                row.get("control_status")
            ),

        "status":
            clean_string(
                row.get("status")
            ),
    }

    cursor.execute(
        """
        INSERT INTO findings (
            finding_id,
            asset_id,
            source,
            cve_id,
            cvss_score,
            epss_score,
            exploit_available,
            title,
            description,
            severity,
            raw_data,
            created_at,
            updated_at
        )
        VALUES (
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            %s,
            CURRENT_TIMESTAMP,
            CURRENT_TIMESTAMP
        )
        ON CONFLICT (finding_id)
        DO UPDATE SET
            asset_id = EXCLUDED.asset_id,
            source = EXCLUDED.source,
            cve_id = EXCLUDED.cve_id,
            cvss_score = EXCLUDED.cvss_score,
            epss_score = EXCLUDED.epss_score,
            exploit_available = EXCLUDED.exploit_available,
            title = EXCLUDED.title,
            description = EXCLUDED.description,
            severity = EXCLUDED.severity,
            raw_data = EXCLUDED.raw_data,
            updated_at = CURRENT_TIMESTAMP
        """,
        (
            db_finding_id,
            asset_id,
            "prowler",
            cve_id,
            cvss_score,
            epss_score,
            exploit_available,
            title,
            description,
            severity,
            Json(raw_data),
        )
    )

    return db_finding_id


# ============================================================
# Main loader
# ============================================================

def load_prowler_csv(csv_file):
    """
    Load normalized Prowler CSV into PostgreSQL.
    """

    logger.info(
        "Loading Prowler CSV: %s",
        csv_file
    )

    # --------------------------------------------------------
    # Read CSV
    # --------------------------------------------------------

    df = pd.read_csv(
        csv_file,
        dtype=object,
        keep_default_na=True
    )

    if df.empty:
        raise RuntimeError(
            "Prowler normalized CSV is empty."
        )

    logger.info(
        "Rows found: %d",
        len(df)
    )

    # --------------------------------------------------------
    # Validate required columns
    # --------------------------------------------------------

    required_columns = [
        "finding_id",
        "resource_uid",
        "asset_name",
        "severity",
        "status",
    ]

    missing_columns = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing_columns:
        raise RuntimeError(
            "Missing required columns: "
            + ", ".join(missing_columns)
        )

    # --------------------------------------------------------
    # Database
    # --------------------------------------------------------

    conn = connect_database()

    try:
        cursor = conn.cursor()

        asset_ids = set()
        finding_ids = set()

        # ----------------------------------------------------
        # Process every Prowler finding
        # ----------------------------------------------------

        for index, row in df.iterrows():

            resource_uid = clean_string(
                row.get("resource_uid")
            )

            if not resource_uid:
                logger.warning(
                    "Row %d has no resource_uid. Skipping.",
                    index + 1
                )
                continue

            asset_id = generate_asset_id(
                resource_uid
            )

            # Asset
            upsert_asset(
                cursor,
                row,
                asset_id
            )

            asset_ids.add(asset_id)

            # Finding
            db_finding_id = upsert_finding(
                cursor,
                row,
                asset_id
            )

            finding_ids.add(
                db_finding_id
            )

        # ----------------------------------------------------
        # Commit
        # ----------------------------------------------------

        conn.commit()

        logger.info(
            "Database transaction committed successfully."
        )

        cursor.close()

        return {
            "rows_processed": len(df),
            "assets_processed": len(asset_ids),
            "findings_processed": len(finding_ids),
        }

    except Exception:

        conn.rollback()

        logger.exception(
            "Database transaction failed. Rolled back."
        )

        raise

    finally:

        conn.close()

        logger.info(
            "Database connection closed."
        )


# ============================================================
# Validation
# ============================================================

def validate_database():
    """
    Validate Prowler records after insertion.
    """

    conn = connect_database()

    try:
        cursor = conn.cursor()

        # ----------------------------------------------------
        # Prowler finding count
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM findings
            WHERE LOWER(source) = 'prowler'
            """
        )

        prowler_findings = cursor.fetchone()[0]

        # ----------------------------------------------------
        # Prowler asset count
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT COUNT(DISTINCT asset_id)
            FROM findings
            WHERE LOWER(source) = 'prowler'
            """
        )

        prowler_assets = cursor.fetchone()[0]

        # ----------------------------------------------------
        # Severity distribution
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT severity, COUNT(*)
            FROM findings
            WHERE LOWER(source) = 'prowler'
            GROUP BY severity
            ORDER BY
                CASE severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    WHEN 'info' THEN 5
                    ELSE 6
                END
            """
        )

        severity_rows = cursor.fetchall()

        # ----------------------------------------------------
        # Sample joined records
        # ----------------------------------------------------

        cursor.execute(
            """
            SELECT
                f.finding_id,
                f.source,
                f.severity,
                f.title,
                a.asset_id,
                a.asset_name
            FROM findings f
            JOIN assets a
                ON f.asset_id = a.asset_id
            WHERE LOWER(f.source) = 'prowler'
            ORDER BY f.created_at DESC
            LIMIT 5
            """
        )

        sample_rows = cursor.fetchall()

        # ----------------------------------------------------
        # Output
        # ----------------------------------------------------

        print()
        print("=" * 60)
        print(" Prowler Database Validation")
        print("=" * 60)

        print(
            f"\nProwler findings in DB: {prowler_findings}"
        )

        print(
            f"Unique Prowler assets: {prowler_assets}"
        )

        print("\nSeverity distribution:")

        for severity, count in severity_rows:
            print(
                f"   {severity}: {count}"
            )

        print("\nSample findings:")

        for row in sample_rows:
            print(
                f"   {row[0]} | "
                f"{row[1]} | "
                f"{row[2]} | "
                f"{row[4]} | "
                f"{row[5]}"
            )

        print()
        print("=" * 60)

        if prowler_findings > 0:
            print(
                " Prowler data is present in PostgreSQL."
            )
        else:
            print(
                " No Prowler findings found."
            )

        print("=" * 60)

        cursor.close()

    finally:
        conn.close()


# ============================================================
# Entry point
# ============================================================

def main():

    print()
    print("=" * 60)
    print(" CyberFinGuard - Prowler DB Loader")
    print("=" * 60)

    try:

        # ----------------------------------------------------
        # Find latest normalized Prowler file
        # ----------------------------------------------------

        csv_file = find_latest_normalized_file()

        print()
        print("Using normalized file:")
        print(csv_file)

        # ----------------------------------------------------
        # Load
        # ----------------------------------------------------

        result = load_prowler_csv(
            csv_file
        )

        print()
        print("=" * 60)
        print(" Load completed successfully")
        print("=" * 60)

        print(
            f"Rows processed: "
            f"{result['rows_processed']}"
        )

        print(
            f"Assets processed: "
            f"{result['assets_processed']}"
        )

        print(
            f"Findings processed: "
            f"{result['findings_processed']}"
        )

        # ----------------------------------------------------
        # Validate
        # ----------------------------------------------------

        validate_database()

    except Exception as exc:

        print()
        print("[ERROR]")
        print(str(exc))

        raise


if __name__ == "__main__":
    main()