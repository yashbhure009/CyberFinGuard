"""
Unified Finding Schema
All ingestors normalize to this format
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, List
from datetime import datetime


@dataclass
class UnifiedFinding:
    """Unified finding format for all tools"""
    
    # ============================================================
    # CORE IDENTIFIERS (same across all tools)
    # ============================================================
    finding_id: str
    asset_id: str
    source: str  # siem | edr | vuln | iam | cspm | threat_intel
    severity: str  # critical | high | medium | low | info
    
    # ============================================================
    # FINDING DETAILS
    # ============================================================
    title: str
    description: str
    
    # ============================================================
    # OPTIONAL THREAT INTEL
    # ============================================================
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    cisa_kev: bool = False
    
    # ============================================================
    # CONTROL STATUS
    # ============================================================
    mfa_enabled: Optional[bool] = None
    patching_status: Optional[str] = None
    waf_enabled: Optional[bool] = None
    edr_enabled: Optional[bool] = None
    
    # ============================================================
    # MITRE / COMPLIANCE
    # ============================================================
    mitre_technique: Optional[str] = None
    framework_tags: List[str] = field(default_factory=list)
    
    # ============================================================
    # RAW DATA (tool-specific)
    # ============================================================
    detail: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[str] = None


# ============================================================
# SOURCE MAPPING
# ============================================================

SOURCE_MAPPING = {
    'wazuh': 'siem',
    'zap': 'vuln',
    'nmap': 'vuln',
    'nuclei': 'vuln',
    'prowler': 'cspm',
    'keycloak': 'iam',
    'threat_intel': 'threat_intel',
}


# ============================================================
# SEVERITY NORMALIZATION
# ============================================================

def normalize_severity(value):
    """Normalize severity to standard values"""
    if value is None:
        return 'info'
    
    severity = str(value).strip().lower()
    
    mapping = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'moderate': 'medium',
        'low': 'low',
        'info': 'info',
        'informational': 'info',
    }
    
    return mapping.get(severity, 'info')


# ============================================================
# ASSET ID MAPPING (same across all tools)
# ============================================================

ASSET_ID_MAPPING = {
    # Wazuh
    'agent_001': 'web-server-01',
    'agent_002': 'db-server-01',
    'agent_003': 'api-server-01',
    
    # Nmap / Nuclei
    'network_target': 'network-target',
    'web_target': 'web-target',
    
    # Prowler
    'aws_': 'aws-resource',
    
    # Keycloak
    'identity_service': 'identity-service',
}


def normalize_asset_id(asset_id):
    """Normalize asset ID to consistent format"""
    if not asset_id:
        return 'unknown-asset'
    
    # Check mapping
    for prefix, replacement in ASSET_ID_MAPPING.items():
        if asset_id.startswith(prefix):
            return replacement
    
    return asset_id