"""Query-time compliance mapping for the current backend architecture.

This module is intentionally side-effect free. It ports the useful rule data
from the compliance branches without their legacy database interface or
framework_tags schema dependency.
"""

from typing import Any, TypedDict


class FrameworkMapping(TypedDict):
    framework: str
    control_id: str | None
    match_method: str
    confidence: str


FRAMEWORK_TAGS = {
    "injection": ["ISO27001-A.14.2.5", "NIST-CSF-PR.DS-2", "CIS-4.1", "RBI-3.2", "SEBI-2.1"],
    "input_validation": ["ISO27001-A.14.2.5", "NIST-CSF-PR.IP-1", "CIS-4.1", "RBI-3.2", "SEBI-2.1"],
    "path_traversal": ["ISO27001-A.13.1.1", "NIST-CSF-PR.AC-5", "CIS-9.1", "RBI-5.1", "SEBI-3.2"],
    "memory_safety": ["ISO27001-A.12.2.1", "NIST-CSF-DE.CM-3", "CIS-10.1", "RBI-6.1", "SEBI-4.1"],
    "auth": ["ISO27001-A.9.4.2", "NIST-CSF-PR.AC-7", "CIS-5.2", "RBI-4.1", "SEBI-3.1"],
    "access_control": ["ISO27001-A.9.2.3", "NIST-CSF-PR.AC-4", "CIS-1.16", "RBI-4.2", "SEBI-3.1"],
    "info_exposure": ["ISO27001-A.12.6", "NIST-CSF-PR.DS-1", "CIS-3.3", "RBI-5.2", "SEBI-3.3"],
    "crypto": ["ISO27001-A.10.1.1", "NIST-CSF-PR.DS-2", "CIS-3.10", "RBI-5.2", "SEBI-3.3"],
    "resource": ["ISO27001-A.12.2.1", "NIST-CSF-DE.CM-3", "CIS-10.1", "RBI-6.1", "SEBI-4.1"],
    "supply_chain": ["ISO27001-A.12.6.1", "NIST-CSF-PR.DS-1", "CIS-3.3", "RBI-5.2", "SEBI-3.3"],
    "cloud_config": ["ISO27001-A.13.2.1", "NIST-CSF-PR.DS-1", "CIS-3.3", "RBI-5.2", "SEBI-3.3"],
    "web_hardening": ["ISO27001-A.14.2.5", "NIST-CSF-PR.IP-1", "CIS-4.1", "RBI-3.2", "SEBI-2.1"],
    "iam": ["ISO27001-A.9.4.2", "NIST-CSF-PR.AC-7", "CIS-5.3", "RBI-4.2", "SEBI-3.1"],
    "network": ["ISO27001-A.13.1.1", "NIST-CSF-PR.AC-5", "CIS-9.1", "RBI-5.1", "SEBI-3.2"],
    "race": ["ISO27001-A.12.2.1", "NIST-CSF-DE.CM-3", "CIS-10.1", "RBI-6.1", "SEBI-4.1"],
}

# Ordered to preserve the more specific branch behavior before broad terms.
SOURCE_TITLE_RULES = [
    ("zap", "cross site", "injection"), ("zap", "cross-site", "injection"), ("zap", "xss", "injection"), ("zap", "sql", "injection"),
    ("zap", "csrf", "injection"), ("zap", "anti-csrf", "injection"),
    ("zap", "clickjacking", "web_hardening"), ("zap", "csp", "web_hardening"),
    ("zap", "content security", "web_hardening"), ("zap", "cross-domain", "web_hardening"),
    ("zap", "cors", "web_hardening"), ("zap", "header", "web_hardening"),
    ("zap", "server leaks", "info_exposure"), ("zap", "cache-control", "info_exposure"),
    ("zap", "information disclosure", "info_exposure"), ("zap", "suspicious comment", "info_exposure"),
    ("zap", "vulnerable js", "supply_chain"), ("zap", "sub resource", "web_hardening"),
    ("zap", "authentication", "auth"),
    ("nmap", "open port", "network"),
    ("nuclei", "xss", "injection"), ("nuclei", "cross-site", "injection"),
    ("nuclei", "open redirect", "injection"), ("nuclei", "sql", "injection"),
    ("nuclei", "rce", "injection"), ("nuclei", "command", "injection"),
    ("wazuh", "ssh", "auth"), ("wazuh", "login", "auth"), ("wazuh", "auth", "auth"),
    ("wazuh", "malware", "memory_safety"),
    ("prowler", "iam", "iam"), ("prowler", "s3", "cloud_config"),
    ("prowler", "bucket", "cloud_config"), ("prowler", "public", "cloud_config"),
    ("keycloak", "mfa", "iam"), ("keycloak", "user", "iam"),
    ("keycloak", "role", "iam"), ("keycloak", "authentication", "iam"),
    ("openvas", "remote code", "injection"), ("openvas", "sql injection", "injection"),
    ("openvas", "cross-site", "injection"), ("openvas", "xss", "injection"),
]

CWE_TO_FAMILY = {
    **{f"CWE-{value}": "injection" for value in (74, 77, 78, 79, 80, 88, 89, 94, 134, 150, 352, 444, 601, 1336)},
    **{f"CWE-{value}": "input_validation" for value in (17, 20, 184, 693, 697)},
    **{f"CWE-{value}": "path_traversal" for value in (22, 23, 29, 59, 552, 918)},
    **{f"CWE-{value}": "memory_safety" for value in (119, 120, 121, 122, 123, 125, 130, 190, 369, 401, 416, 459, 476, 617, 772, 787, 824, 908)},
    **{f"CWE-{value}": "auth" for value in (287, 288, 306, 307, 522, 798, 799, 940)},
    **{f"CWE-{value}": "access_control" for value in (264, 266, 269, 284, 285, 425, 639, 732, 862, 863)},
    **{f"CWE-{value}": "info_exposure" for value in (200, 203, 204, 598, 611)},
    **{f"CWE-{value}": "crypto" for value in (319, 327)},
    **{f"CWE-{value}": "resource" for value in (400, 404, 770, 835, 1333)},
    **{f"CWE-{value}": "supply_chain" for value in (73, 434, 494)},
    "CWE-502": "memory_safety",
    "CWE-367": "race",
}


def _extract_cwe(finding: dict[str, Any]) -> list[str]:
    raw_data = finding.get("raw_data") or finding.get("detail") or {}
    if isinstance(raw_data, str):
        import json
        try:
            raw_data = json.loads(raw_data)
        except (json.JSONDecodeError, TypeError):
            raw_data = {}
    values = [finding.get("cwe_id"), finding.get("cwe"), raw_data.get("cwe_id") if isinstance(raw_data, dict) else None, raw_data.get("cwe") if isinstance(raw_data, dict) else None]
    text = " ".join(str(value or "") for value in values).replace(",", " ")
    return [part.upper() for part in text.split() if part.upper().startswith("CWE-")]


def _mappings_for_family(family: str, method: str) -> list[FrameworkMapping]:
    mappings: list[FrameworkMapping] = []
    for tag in FRAMEWORK_TAGS[family]:
        if tag.startswith("ISO27001-"):
            framework, control_id = "ISO 27001", tag.removeprefix("ISO27001-")
        elif tag.startswith("NIST-CSF-"):
            framework, control_id = "NIST CSF", tag.removeprefix("NIST-CSF-")
        elif tag.startswith("CIS-"):
            framework, control_id = "CIS Controls", tag.removeprefix("CIS-")
        elif tag.startswith("RBI-"):
            framework, control_id = "RBI CSCF", tag.removeprefix("RBI-")
        else:
            framework, control_id = "SEBI CSCRF", tag.removeprefix("SEBI-")
        mappings.append({"framework": framework, "control_id": control_id, "match_method": method, "confidence": "high" if method == "source_title_rule" else "medium"})
    return mappings


def map_finding_to_frameworks(finding: dict[str, Any]) -> list[FrameworkMapping]:
    source = str(finding.get("source") or "").lower()
    title = str(finding.get("title") or "").lower()
    for rule_source, keyword, family in SOURCE_TITLE_RULES:
        if source == rule_source and keyword in title:
            return _mappings_for_family(family, "source_title_rule")

    for cwe in _extract_cwe(finding):
        family = CWE_TO_FAMILY.get(cwe)
        if family:
            return _mappings_for_family(family, "cwe_fallback")

    return [{"framework": "Unmapped", "control_id": None, "match_method": "unmapped", "confidence": "none"}]
