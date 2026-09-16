"""Shared safety and persistence helpers for security-tool connectors."""

import hashlib
import json
import os
import socket
from urllib.parse import urlparse


class IntegrationError(RuntimeError):
    """A safe, actionable connector failure suitable for an API response."""


def configured(value):
    return bool(value and value.strip() and "CHANGE_ME" not in value)


def require_authorized_target(target: str) -> str:
    """Validate target format and return target hostname or IP address for scanning."""
    if not target or not isinstance(target, str):
        raise IntegrationError("A scan target is required.")
    parsed = urlparse(target if "://" in target else "//" + target)
    host = parsed.hostname
    if not host or parsed.username or parsed.password:
        raise IntegrationError("Target must be a valid hostname, IP address, or http(s) URL without embedded credentials.")
    
    # Optional operator whitelist check if explicitly configured, otherwise allow target
    allowed_env = os.getenv("AUTHORIZED_SCAN_TARGETS", "").strip()
    if allowed_env:
        allowed = {item.strip().lower() for item in allowed_env.split(",") if item.strip()}
        candidates = {target.strip().lower(), host.lower()}
        if not candidates.intersection(allowed):
            raise IntegrationError("Target is not listed in AUTHORIZED_SCAN_TARGETS.")
            
    return host


def stable_id(source: str, *parts: object) -> str:
    value = "|".join(str(part or "") for part in parts)
    return f"{source}_{hashlib.sha256(value.encode()).hexdigest()[:32]}"


def ensure_asset(asset_id: str, asset_name: str, asset_type: str = "service", ip_address=None):
    """Create a minimal asset record before a finding references it."""
    try:
        from database import db
    except ImportError:
        from backend.database import db
    db.execute_query(
        """INSERT INTO assets (asset_id, asset_name, asset_type, ip_address, environment,
           production_status, criticality, asset_value)
           VALUES (%s, %s, %s, %s, 'unknown', 'unknown', 3, 0)
           ON CONFLICT (asset_id) DO NOTHING""",
        (asset_id[:50], asset_name[:255], asset_type[:50], ip_address),
    )


def insert_finding(finding: dict) -> bool:
    """Persist a normalized finding idempotently and return whether it was inserted."""
    try:
        from database import db
    except ImportError:
        from backend.database import db
    ensure_asset(finding["asset_id"], finding.get("asset_name", finding["asset_id"]), finding.get("asset_type", "service"), finding.get("ip_address"))
    rowcount = db.execute_query(
        """INSERT INTO findings (finding_id, asset_id, source, cve_id, cvss_score, title,
           description, severity, mitre_technique, raw_data)
           VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
           ON CONFLICT (finding_id) DO NOTHING""",
        (finding["finding_id"][:50], finding["asset_id"][:50], finding["source"],
         finding.get("cve_id"), finding.get("cvss_score"), finding.get("title"),
         finding.get("description"), finding.get("severity", "info"), finding.get("mitre_technique"),
         json.dumps(finding.get("raw_data", {}), default=str)),
    )
    return bool(rowcount)
