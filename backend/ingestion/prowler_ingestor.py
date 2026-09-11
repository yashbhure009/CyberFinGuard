import os
import sys
import json
import hashlib
import logging
from dataclasses import dataclass

import pandas as pd
import paramiko


# ============================================================
# CONFIGURATION
# ============================================================

@dataclass
class ProwlerConfig:
    # Kali SSH
    ssh_host: str = "192.168.56.101"
    ssh_port: int = 22
    ssh_username: str = "kali"

    # Prowler project directory
    prowler_dir: str = "/home/kali/prowler"

    # Prowler services
    # Use spaces, NOT commas.
    # Example: "iam s3 ec2"
    services: str = "iam"

    # Local output directory
    output_dir: str = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "prowler_results"
    )


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(message)s"
)

logger = logging.getLogger(__name__)


# ============================================================
# NORMALIZED SCHEMA
# ============================================================

NORMALIZED_COLUMNS = [
    "source",
    "finding_id",
    "resource_uid",
    "asset_name",
    "asset_id",
    "finding_type",
    "title",
    "severity",
    "status",
    "description",
    "cve_id",
    "cvss_score",
    "epss_score",
    "exploit_available",
    "control_status",
    "region",
    "timestamp",
    "remediation",
]


# ============================================================
# PROWLER INGESTOR
# ============================================================

class ProwlerIngestor:

    def __init__(self, config=None):

        self.config = config or ProwlerConfig()

        self.ssh_client = None
        self.sftp_client = None

        self.remote_credentials_file = (
            "/tmp/cyberfinguard_aws_credentials"
        )

        os.makedirs(
            self.config.output_dir,
            exist_ok=True
        )

    # ========================================================
    # SSH CONNECTION
    # ========================================================

    def connect_ssh(self):

        print("\n[1/6] Connecting to Kali...")

        password = os.getenv(
            "KALI_SSH_PASSWORD"
        )

        if not password:

            import getpass

            password = getpass.getpass(
                "Enter Kali SSH password: "
            )

        self.ssh_client = paramiko.SSHClient()

        self.ssh_client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy()
        )

        self.ssh_client.connect(
            hostname=self.config.ssh_host,
            port=self.config.ssh_port,
            username=self.config.ssh_username,
            password=password,
            timeout=15
        )

        self.sftp_client = (
            self.ssh_client.open_sftp()
        )

        print(
            "[OK] Connected to Kali."
        )

    # ========================================================
    # REMOTE COMMAND
    # ========================================================

    def run_remote_command(
        self,
        command,
        timeout=3600
    ):

        stdin, stdout, stderr = (
            self.ssh_client.exec_command(
                command,
                timeout=timeout
            )
        )

        output = stdout.read().decode(
            "utf-8",
            errors="replace"
        )

        error = stderr.read().decode(
            "utf-8",
            errors="replace"
        )

        exit_code = (
            stdout.channel.recv_exit_status()
        )

        return (
            exit_code,
            output,
            error
        )

    # ========================================================
    # CHECK PROWLER
    # ========================================================

    def check_prowler(self):

        print(
            "\n[2/6] Checking Prowler installation..."
        )

        # Prowler is installed inside:
        #
        # /home/kali/prowler/.venv
        #
        # Paramiko starts a non-interactive shell,
        # therefore explicitly activate the environment.

        command = (
            f"cd {self.config.prowler_dir} && "
            "source .venv/bin/activate && "
            "prowler --version"
        )

        exit_code, output, error = (
            self.run_remote_command(
                command
            )
        )

        if exit_code != 0:

            raise RuntimeError(
                "Unable to execute Prowler.\n"
                + error
            )

        version = output.strip()

        print(
            f"[OK] Prowler: {version}"
        )

    # ========================================================
    # PREPARE AWS CREDENTIALS
    # ========================================================

    def prepare_aws_credentials(self):

        print(
            "\n[3/6] Preparing temporary AWS credentials..."
        )

        access_key = os.getenv(
            "AWS_ACCESS_KEY_ID"
        )

        secret_key = os.getenv(
            "AWS_SECRET_ACCESS_KEY"
        )

        session_token = os.getenv(
            "AWS_SESSION_TOKEN"
        )

        region = os.getenv(
            "AWS_DEFAULT_REGION",
            "ap-south-1"
        )

        if not access_key:

            access_key = input(
                "Enter AWS Access Key ID: "
            ).strip()

        if not secret_key:

            import getpass

            secret_key = getpass.getpass(
                "Enter AWS Secret Access Key: "
            )

        if not access_key or not secret_key:

            raise RuntimeError(
                "AWS credentials are required."
            )

        credentials = [
            "[default]",
            f"aws_access_key_id = {access_key}",
            f"aws_secret_access_key = {secret_key}",
        ]

        if session_token:

            credentials.append(
                f"aws_session_token = {session_token}"
            )

        credentials.append(
            f"region = {region}"
        )

        credentials_text = (
            "\n".join(credentials)
            + "\n"
        )

        command = (
            f"cat > {self.remote_credentials_file} <<'EOF'\n"
            f"{credentials_text}"
            "EOF\n"
            f"chmod 600 {self.remote_credentials_file}"
        )

        exit_code, output, error = (
            self.run_remote_command(
                command
            )
        )

        if exit_code != 0:

            raise RuntimeError(
                "Failed to create temporary AWS "
                "credentials file.\n"
                + error
            )

        print(
            "[OK] Temporary credentials uploaded."
        )

    # ========================================================
    # RUN PROWLER
    # ========================================================

    def run_prowler(self):

        print(
            "\n[4/6] Running Prowler..."
        )

        services = (
            self.config.services.split()
        )

        service_arguments = (
            " ".join(services)
        )

        print(
            f"Services: {service_arguments}"
        )

        # Explicitly activate Prowler .venv.
        #
        # We do NOT use find -newer afterwards.
        # Instead, we extract the exact result paths
        # printed by Prowler itself.

        command = (
            f"cd {self.config.prowler_dir} && "
            "source .venv/bin/activate && "
            f"export AWS_SHARED_CREDENTIALS_FILE="
            f"{self.remote_credentials_file} && "
            f"prowler aws --services "
            f"{service_arguments}"
        )

        exit_code, output, error = (
            self.run_remote_command(
                command,
                timeout=7200
            )
        )

        # Display Prowler output
        print(output)

        # Prowler exit code 3 means:
        # scan completed but security findings failed.
        #
        # Those failures are valid findings.

        if exit_code == 3:

            print(
                "[INFO] Prowler scan completed with "
                "failed security findings."
            )

            print(
                "[INFO] Failed checks are valid security findings."
            )

        elif exit_code != 0:

            print(
                "[ERROR] Prowler stderr:"
            )

            print(error)

            raise RuntimeError(
                f"Prowler execution failed "
                f"with exit code {exit_code}."
            )

        # ----------------------------------------------------
        # Extract exact result paths from Prowler output
        # ----------------------------------------------------

        result_files = []

        for line in output.splitlines():

            line = line.strip()

            if line.startswith("- JSON-OCSF:"):

                path = line.split(
                    "- JSON-OCSF:",
                    1
                )[1].strip()

                if path:
                    result_files.append(path)

            elif line.startswith("- CSV:"):

                path = line.split(
                    "- CSV:",
                    1
                )[1].strip()

                if path:
                    result_files.append(path)

            elif line.startswith("- HTML:"):

                path = line.split(
                    "- HTML:",
                    1
                )[1].strip()

                if path:
                    result_files.append(path)

        # ----------------------------------------------------
        # Validate result paths
        # ----------------------------------------------------

        if not result_files:

            raise RuntimeError(
                "Prowler completed successfully, but "
                "result file paths could not be detected."
            )

        print(
            f"[OK] Prowler generated "
            f"{len(result_files)} result files."
        )

        for path in result_files:

            print(
                f"[OK] {path}"
            )

        return result_files

    # ========================================================
    # DOWNLOAD RESULTS
    # ========================================================

    def download_results(
        self,
        remote_files
    ):

        print(
            "\n[5/6] Downloading Prowler results..."
        )

        downloaded_files = []

        for remote_path in remote_files:

            filename = os.path.basename(
                remote_path
            )

            local_path = os.path.join(
                self.config.output_dir,
                filename
            )

            print(
                f"Downloading: {filename}"
            )

            self.sftp_client.get(
                remote_path,
                local_path
            )

            downloaded_files.append(
                local_path
            )

        if not downloaded_files:

            raise RuntimeError(
                "No Prowler result files were downloaded."
            )

        print(
            f"\n[OK] Downloaded "
            f"{len(downloaded_files)} result files."
        )

        return downloaded_files

    # ========================================================
    # GENERATE DETERMINISTIC ASSET ID
    # ========================================================

    @staticmethod
    def generate_asset_id(
        resource_uid
    ):

        if not resource_uid:

            raise ValueError(
                "RESOURCE_UID cannot be empty."
            )

        digest = hashlib.sha256(
            resource_uid.encode(
                "utf-8"
            )
        ).hexdigest()[:16]

        return (
            f"aws_{digest}"
        )

    # ========================================================
    # NORMALIZE SEVERITY
    # ========================================================

    @staticmethod
    def normalize_severity(
        value
    ):

        if value is None:

            return "info"

        severity = (
            str(value)
            .strip()
            .lower()
        )

        valid = {
            "critical",
            "high",
            "medium",
            "low",
            "info"
        }

        if severity in valid:

            return severity

        return "info"

    # ========================================================
    # NORMALIZE CONTROL STATUS
    # ========================================================

    @staticmethod
    def normalize_control_status(
        status
    ):

        status = (
            str(status)
            .strip()
            .upper()
        )

        mapping = {
            "PASS": "effective",
            "FAIL": "ineffective",
            "MUTED": "muted",
        }

        return mapping.get(
            status,
            "unknown"
        )

    # ========================================================
    # NORMALIZE FINDING
    # ========================================================

    def normalize_finding(
        self,
        row
    ):

        # ----------------------------------------------------
        # Stable Prowler RESOURCE_UID
        # ----------------------------------------------------

        resource_uid = str(
            row.get(
                "RESOURCE_UID",
                ""
            )
        ).strip()

        if not resource_uid:

            resource_uid = (
                "unknown-resource"
            )

        # ----------------------------------------------------
        # Human-readable resource name
        # ----------------------------------------------------

        asset_name = str(
            row.get(
                "RESOURCE_NAME",
                ""
            )
        ).strip()

        if not asset_name:

            asset_name = resource_uid

        # ----------------------------------------------------
        # Deterministic asset ID
        # ----------------------------------------------------

        asset_id = (
            self.generate_asset_id(
                resource_uid
            )
        )

        # ----------------------------------------------------
        # Finding ID
        # ----------------------------------------------------

        finding_id = str(
            row.get(
                "FINDING_UID",
                ""
            )
        ).strip()

        if not finding_id:

            check_id = str(
                row.get(
                    "CHECK_ID",
                    ""
                )
            ).strip()

            account_uid = str(
                row.get(
                    "ACCOUNT_UID",
                    ""
                )
            ).strip()

            region = str(
                row.get(
                    "REGION",
                    ""
                )
            ).strip()

            finding_id = (
                f"prowler-{check_id}-"
                f"{account_uid}-{region}-"
                f"{asset_id}"
            )

        # ----------------------------------------------------
        # Status
        # ----------------------------------------------------

        status = str(
            row.get(
                "STATUS",
                ""
            )
        ).strip().upper()

        if not status:

            status = "UNKNOWN"

        # ----------------------------------------------------
        # Timestamp
        # ----------------------------------------------------

        timestamp = row.get(
            "TIMESTAMP",
            None
        )

        # ----------------------------------------------------
        # NORMALIZED RECORD
        # ----------------------------------------------------

        normalized = {

            "source":
                "Prowler",

            "finding_id":
                finding_id,

            "resource_uid":
                resource_uid,

            "asset_name":
                asset_name,

            "asset_id":
                asset_id,

            "finding_type":
                "Cloud/IAM Configuration",

            "title":
                str(
                    row.get(
                        "CHECK_TITLE",
                        ""
                    )
                ).strip(),

            "severity":
                self.normalize_severity(
                    row.get(
                        "SEVERITY",
                        "info"
                    )
                ),

            "status":
                status,

            "description":
                str(
                    row.get(
                        "DESCRIPTION",
                        ""
                    )
                ).strip(),

            # Prowler IAM configuration findings do not
            # inherently have CVE/CVSS/EPSS values.
            # Therefore these remain NULL.

            "cve_id":
                None,

            "cvss_score":
                None,

            "epss_score":
                None,

            "exploit_available":
                None,

            "control_status":
                self.normalize_control_status(
                    status
                ),

            "region":
                str(
                    row.get(
                        "REGION",
                        ""
                    )
                ).strip(),

            "timestamp":
                timestamp,

            "remediation":
                str(
                    row.get(
                        "REMEDIATION_RECOMMENDATION_TEXT",
                        ""
                    )
                ).strip(),
        }

        # ----------------------------------------------------
        # Preserve complete raw Prowler record
        # ----------------------------------------------------

        normalized["raw_data"] = json.dumps(
            row.to_dict(),
            default=str,
            ensure_ascii=False
        )

        return normalized

    # ========================================================
    # NORMALIZE CSV
    # ========================================================

    def normalize_csv(
        self,
        csv_file
    ):

        print(
            "\n[6/6] Normalizing Prowler findings..."
        )

        # Prowler CSV uses semicolon delimiter.

        df = pd.read_csv(
            csv_file,
            sep=";",
            quotechar='"',
            engine="python"
        )

        if df.empty:

            raise RuntimeError(
                "Prowler CSV is empty."
            )

        normalized_records = []

        for _, row in df.iterrows():

            try:

                record = (
                    self.normalize_finding(
                        row
                    )
                )

                normalized_records.append(
                    record
                )

            except Exception as exc:

                logger.exception(
                    "Failed to normalize finding: %s",
                    exc
                )

        normalized_df = pd.DataFrame(
            normalized_records
        )

        # ----------------------------------------------------
        # Final schema
        # ----------------------------------------------------

        final_columns = (
            NORMALIZED_COLUMNS
            + ["raw_data"]
        )

        for column in final_columns:

            if column not in normalized_df.columns:

                normalized_df[column] = None

        normalized_df = normalized_df[
            final_columns
        ]

        # ----------------------------------------------------
        # Output filename
        # ----------------------------------------------------

        base_name = os.path.splitext(
            os.path.basename(
                csv_file
            )
        )[0]

        output_file = os.path.join(
            self.config.output_dir,
            f"{base_name}_normalized.csv"
        )

        normalized_df.to_csv(
            output_file,
            index=False
        )

        print(
            f"[OK] Normalized "
            f"{len(normalized_df)} findings."
        )

        print(
            f"[OK] Normalized file:"
        )

        print(
            output_file
        )

        # ----------------------------------------------------
        # Validation
        # ----------------------------------------------------

        print(
            "\nNormalization validation:"
        )

        print(
            f"Raw findings: "
            f"{len(df)}"
        )

        print(
            f"Normalized findings: "
            f"{len(normalized_df)}"
        )

        print(
            f"Columns: "
            f"{len(normalized_df.columns)}"
        )

        # ----------------------------------------------------
        # Finding count
        # ----------------------------------------------------

        if len(df) == len(
            normalized_df
        ):

            print(
                "Finding count: PASS"
            )

        else:

            print(
                "Finding count: FAIL"
            )

        # ----------------------------------------------------
        # Finding IDs
        # ----------------------------------------------------

        unique_ids = normalized_df[
            "finding_id"
        ].nunique()

        if unique_ids == len(
            normalized_df
        ):

            print(
                "Finding IDs: PASS"
            )

        else:

            print(
                "Finding IDs: WARNING - duplicates found"
            )

        # ----------------------------------------------------
        # Resource UIDs
        # ----------------------------------------------------

        missing_uids = normalized_df[
            "resource_uid"
        ].isna().sum()

        if missing_uids == 0:

            print(
                "Resource UIDs: PASS"
            )

        else:

            print(
                f"Resource UIDs: WARNING - "
                f"{missing_uids} missing"
            )

        # ----------------------------------------------------
        # Asset IDs
        # ----------------------------------------------------

        missing_asset_ids = normalized_df[
            "asset_id"
        ].isna().sum()

        if missing_asset_ids == 0:

            print(
                "Asset IDs: PASS"
            )

        else:

            print(
                f"Asset IDs: WARNING - "
                f"{missing_asset_ids} missing"
            )

        # ----------------------------------------------------
        # Severity
        # ----------------------------------------------------

        print(
            "\nSeverity distribution:"
        )

        print(
            normalized_df[
                "severity"
            ].value_counts()
        )

        # ----------------------------------------------------
        # Status
        # ----------------------------------------------------

        print(
            "\nStatus distribution:"
        )

        print(
            normalized_df[
                "status"
            ].value_counts()
        )

        # ----------------------------------------------------
        # Control status
        # ----------------------------------------------------

        print(
            "\nControl status distribution:"
        )

        print(
            normalized_df[
                "control_status"
            ].value_counts()
        )

        return output_file

    # ========================================================
    # CLEANUP
    # ========================================================

    def cleanup(self):

        print(
            "\nCleaning temporary credentials..."
        )

        try:

            if self.ssh_client:

                try:

                    self.run_remote_command(
                        "rm -f "
                        "/tmp/cyberfinguard_aws_credentials "
                        "/tmp/cyberfinguard_prowler_scan_started"
                    )

                except Exception:
                    pass

            if self.sftp_client:

                try:

                    self.sftp_client.close()

                except Exception:
                    pass

            if self.ssh_client:

                try:

                    self.ssh_client.close()

                except Exception:
                    pass

            print(
                "[OK] Temporary files removed."
            )

        except Exception as exc:

            print(
                f"[WARNING] Cleanup issue: {exc}"
            )

    # ========================================================
    # COMPLETE PIPELINE
    # ========================================================

    def run(self):

        try:

            # ------------------------------------------------
            # 1. SSH
            # ------------------------------------------------

            self.connect_ssh()

            # ------------------------------------------------
            # 2. Check Prowler
            # ------------------------------------------------

            self.check_prowler()

            # ------------------------------------------------
            # 3. AWS credentials
            # ------------------------------------------------

            self.prepare_aws_credentials()

            # ------------------------------------------------
            # 4. Run Prowler
            # ------------------------------------------------

            remote_files = (
                self.run_prowler()
            )

            # ------------------------------------------------
            # 5. Download results
            # ------------------------------------------------

            downloaded_files = (
                self.download_results(
                    remote_files
                )
            )

            # ------------------------------------------------
            # Find downloaded CSV
            # ------------------------------------------------

            csv_files = [
                f
                for f in downloaded_files
                if f.lower().endswith(".csv")
            ]

            if not csv_files:

                raise RuntimeError(
                    "No Prowler CSV result downloaded."
                )

            csv_file = csv_files[0]

            # ------------------------------------------------
            # 6. Normalize
            # ------------------------------------------------

            normalized_file = (
                self.normalize_csv(
                    csv_file
                )
            )

            print(
                "\n[COMPLETE] Prowler ingestion "
                "+ normalization finished."
            )

            return normalized_file

        except Exception as exc:

            print(
                "\n[ERROR]"
            )

            print(
                str(exc)
            )

            return None

        finally:

            self.cleanup()


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    config = ProwlerConfig()

    ingestor = ProwlerIngestor(
        config
    )

    result = ingestor.run()

    if result:

        sys.exit(0)

    sys.exit(1)