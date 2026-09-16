import os
import sys
import json
import hashlib
import logging
import subprocess
from dataclasses import dataclass

import pandas as pd
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)


@dataclass
class ProwlerConfig:
    # Windows local Prowler
    services: str = "iam s3 ec2"
    output_dir: str = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "prowler_results"
    )


NORMALIZED_COLUMNS = [
    "source", "finding_id", "resource_uid", "asset_name", "asset_id",
    "finding_type", "title", "severity", "status", "description",
    "cve_id", "cvss_score", "epss_score", "exploit_available",
    "control_status", "region", "timestamp", "remediation",
]


class ProwlerIngestor:

    def __init__(self, config=None):
        self.config = config or ProwlerConfig()
        os.makedirs(self.config.output_dir, exist_ok=True)

    # ========================================================
    # CHECK PROWLER
    # ========================================================
    def check_prowler(self):
        print("\n[1/4] Checking Prowler installation...")

        prowler_path = os.getenv("PROWLER_PATH", "prowler")

        result = subprocess.run(
    [prowler_path, "--version"],
    capture_output=True, text=True,
    encoding="utf-8", errors="replace"  # 👈 add kiya
)
        if result.returncode != 0:
            raise RuntimeError(f"Prowler not found. Error: {result.stderr}")
        print(f"[OK] {result.stdout.strip()}")

    # ========================================================
    # RUN PROWLER (Local Windows)
    # ========================================================
    def run_prowler(self):
        print("\n[2/4] Running Prowler scan...")

        prowler_path = os.getenv("PROWLER_PATH", "prowler")

        scan_dir = os.path.join(self.config.output_dir, "raw")
        os.makedirs(scan_dir, exist_ok=True)

        cmd = [
            prowler_path, "aws",
            "--services", *self.config.services.split(),
            "-M", "csv", "json-ocsf",
            "-o", scan_dir,
        ]

        print(f"Command: {' '.join(cmd)}")

        result = subprocess.run(
    cmd, capture_output=True, text=True,
    encoding="utf-8", errors="replace"  # 👈 add kiya
)

        print(result.stdout)

        # Prowler exit code 3 = findings failed (valid)
        if result.returncode not in (0, 3):
            print("[ERROR] Prowler stderr:")
            print(result.stderr)
            raise RuntimeError(
                f"Prowler failed with exit code {result.returncode}"
            )

        # Find generated files
        csv_files = [
            os.path.join(scan_dir, f)
            for f in os.listdir(scan_dir)
            if f.endswith(".csv")
        ]

        if not csv_files:
            raise RuntimeError("No CSV output found from Prowler.")

        print(f"[OK] Found {len(csv_files)} CSV file(s)")
        return csv_files

    # ========================================================
    # ASSET ID
    # ========================================================
    @staticmethod
    def generate_asset_id(resource_uid):
        if not resource_uid:
            raise ValueError("RESOURCE_UID cannot be empty.")
        digest = hashlib.sha256(
            resource_uid.encode("utf-8")
        ).hexdigest()[:16]
        return f"aws_{digest}"

    # ========================================================
    # SEVERITY
    # ========================================================
    @staticmethod
    def normalize_severity(value):
        if value is None:
            return "info"
        severity = str(value).strip().lower()
        valid = {"critical", "high", "medium", "low", "info"}
        return severity if severity in valid else "info"

    # ========================================================
    # CONTROL STATUS
    # ========================================================
    @staticmethod
    def normalize_control_status(status):
        status = str(status).strip().upper()
        return {
            "PASS": "effective",
            "FAIL": "ineffective",
            "MUTED": "muted",
        }.get(status, "unknown")

    # ========================================================
    # NORMALIZE FINDING
    # ========================================================
    def normalize_finding(self, row):
        resource_uid = str(row.get("RESOURCE_UID", "")).strip() or "unknown-resource"
        asset_name = str(row.get("RESOURCE_NAME", "")).strip() or resource_uid
        asset_id = self.generate_asset_id(resource_uid)

        finding_id = str(row.get("FINDING_UID", "")).strip()
        if not finding_id:
            check_id = str(row.get("CHECK_ID", "")).strip()
            account_uid = str(row.get("ACCOUNT_UID", "")).strip()
            region = str(row.get("REGION", "")).strip()
            finding_id = f"prowler-{check_id}-{account_uid}-{region}-{asset_id}"

        status = str(row.get("STATUS", "")).strip().upper() or "UNKNOWN"

        normalized = {
            "source": "Prowler",
            "finding_id": finding_id,
            "resource_uid": resource_uid,
            "asset_name": asset_name,
            "asset_id": asset_id,
            "finding_type": "Cloud/IAM Configuration",
            "title": str(row.get("CHECK_TITLE", "")).strip(),
            "severity": self.normalize_severity(row.get("SEVERITY", "info")),
            "status": status,
            "description": str(row.get("DESCRIPTION", "")).strip(),
            "cve_id": None,
            "cvss_score": None,
            "epss_score": None,
            "exploit_available": None,
            "control_status": self.normalize_control_status(status),
            "region": str(row.get("REGION", "")).strip(),
            "timestamp": row.get("TIMESTAMP", None),
            "remediation": str(
                row.get("REMEDIATION_RECOMMENDATION_TEXT", "")
            ).strip(),
        }

        normalized["raw_data"] = json.dumps(
            row.to_dict(), default=str, ensure_ascii=False
        )
        return normalized

    # ========================================================
    # NORMALIZE CSV
    # ========================================================
    def normalize_csv(self, csv_file):
        print("\n[3/4] Normalizing findings...")

        df = pd.read_csv(
            csv_file, sep=";", quotechar='"', engine="python"
        )

        if df.empty:
            raise RuntimeError("Prowler CSV is empty.")

        records = []
        for _, row in df.iterrows():
            try:
                records.append(self.normalize_finding(row))
            except Exception as exc:
                logger.exception("Normalize failed: %s", exc)

        normalized_df = pd.DataFrame(records)

        final_columns = NORMALIZED_COLUMNS + ["raw_data"]
        for col in final_columns:
            if col not in normalized_df.columns:
                normalized_df[col] = None
        normalized_df = normalized_df[final_columns]

        base_name = os.path.splitext(os.path.basename(csv_file))[0]
        output_file = os.path.join(
            self.config.output_dir, f"{base_name}_normalized.csv"
        )
        normalized_df.to_csv(output_file, index=False)

        print(f"[OK] Normalized {len(normalized_df)} findings")
        print(f"[OK] File: {output_file}")
        return output_file

    # ========================================================
    # RUN
    # ========================================================
    def run(self):
        try:
            self.check_prowler()
            csv_files = self.run_prowler()
            normalized_file = self.normalize_csv(csv_files[0])
            print("\n[COMPLETE] Prowler ingestion finished.")
            return normalized_file
        except Exception as exc:
            print(f"\n[ERROR] {exc}")
            return None


# ============================================================
# MAIN — Standalone Test
# ============================================================
if __name__ == "__main__":
    ingestor = ProwlerIngestor()
    result = ingestor.run()
    if result:
        print(f"\n✅ Output: {result}")
        sys.exit(0)
    sys.exit(1)