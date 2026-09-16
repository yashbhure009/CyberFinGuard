"""
CyberFinGuard — Unified Ingestion Runner
Outputs unified findings JSON for downstream models
With Nexora website integration (full pipeline)
"""

import os
import sys
import json
import logging
import socket
from datetime import datetime

# ============================================================
# PATH SETUP
# ============================================================
ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.join(ROOT_DIR, 'backend')
sys.path.insert(0, ROOT_DIR)
sys.path.insert(0, BACKEND_DIR)

from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Output directory
OUTPUT_DIR = os.getenv('UNIFIED_OUTPUT_DIR', 'data/unified_findings')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# User config file
SCAN_CONFIG_PATH = os.path.join(ROOT_DIR, 'scan_config.json')

# Nexora target (default)
NEXORA_URL = "https://desktop-72ti05t.tailc1051b.ts.net/"

# Hardcoded IPv4 (DNS multiple IPs de raha hai)
NEXORA_IP = "103.84.155.217"


# ============================================================
# USER CONFIG LOADER
# ============================================================

def load_user_config():
    """Load user config from scan_config.json if it exists."""
    if not os.path.exists(SCAN_CONFIG_PATH):
        logger.info("No scan_config.json found — using defaults")
        return {}
    try:
        with open(SCAN_CONFIG_PATH, 'r', encoding='utf-8') as fp:
            cfg = json.load(fp)
        logger.info(f"✅ Loaded user config from {SCAN_CONFIG_PATH}")
        return cfg
    except Exception as e:
        logger.warning(f"Failed to load user config: {e}")
        return {}


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def _safe_float(value, default=0.0):
    if value is None or value == "" or str(value).lower() in ("unknown", "n/a", "null"):
        return default
    try:
        return float(value)
    except (ValueError, TypeError):
        return default


def _safe_string(value, default="None"):
    if value is None or value == "" or str(value).lower() in ("unknown", "n/a", "null"):
        return default
    return str(value)


def parse_raw_data(raw):
    if not raw:
        return {}
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}
    return {}


def get_ip_from_hostname(hostname):
    """Hostname se IPv4 nikalo"""
    try:
        return socket.gethostbyname(hostname)
    except:
        return NEXORA_IP  # Fallback


# ============================================================
# INGESTOR RUNNERS
# ============================================================

def run_zap_manual(target_url=None):
    """ZAP Manual scan — 92 findings (Nexora)"""
    try:
        logger.info("=" * 60)
        logger.info("🕷️ Running ZAP MANUAL scan...")
        from backend.ingestion.zap_manual_scan import ZAPManualScan
        
        scanner = ZAPManualScan()
        result = scanner.run(target_url or NEXORA_URL)
        logger.info(f"✅ ZAP Manual: {result}")
        return result
    except Exception as e:
        logger.error(f"❌ ZAP Manual failed: {e}")
        return {"source": "zap", "error": str(e)}


def run_nmap(target=None):
    """Nmap scan — Nexora IP"""
    try:
        target = target or NEXORA_IP
        logger.info("=" * 60)
        logger.info(f"🔍 Running Nmap on {target}...")
        from backend.ingestion.nmap_ingestor import NmapIngestor
        ingestor = NmapIngestor()
        result = ingestor.run(target=target)
        logger.info(f"✅ Nmap: {result}")
        return result
    except Exception as e:
        logger.error(f"❌ Nmap failed: {e}")
        return {"source": "nmap", "error": str(e)}


def run_nuclei(target=None, severity='low,medium,high,critical'):
    """Nuclei scan — httpbin.org test target"""
    try:
        target = target or 'https://httpbin.org'
        logger.info(f"🎯 Running Nuclei on {target}")
        logger.info(f"   Severity: {severity}")

        from backend.ingestion.nuclei_ingestor import NucleiIngestor
        ingestor = NucleiIngestor()
        result = ingestor.run(target=target, severity=severity)
        logger.info(f"✅ Nuclei: {result}")
        return result
    except Exception as e:
        logger.error(f"❌ Nuclei failed: {e}")
        return {"source": "nuclei", "error": str(e)}


def run_wazuh():
    """Wazuh — Local Docker"""
    try:
        logger.info("=" * 60)
        logger.info("📊 Running Wazuh Ingestor...")
        from backend.ingestion.wazuh_ingestor import WazuhIngestor
        ingestor = WazuhIngestor()
        result = ingestor.run()
        logger.info(f"✅ Wazuh: {result}")
        return result
    except Exception as e:
        logger.error(f"❌ Wazuh failed: {e}")
        return {"source": "wazuh", "error": str(e)}


def run_prowler():
    """Prowler — AWS scan"""
    try:
        logger.info("=" * 60)
        logger.info("☁️ Running Prowler Ingestor...")
        from backend.ingestion.prowler_ingestor import ProwlerIngestor
        ingestor = ProwlerIngestor()
        result = ingestor.run()
        logger.info(f"✅ Prowler: {result}")
        return {"source": "prowler", "output": result}
    except Exception as e:
        logger.error(f"❌ Prowler failed: {e}")
        return {"source": "prowler", "error": str(e)}


def run_keycloak():
    """Keycloak — Local Docker (8090)"""
    try:
        logger.info("=" * 60)
        logger.info("🔐 Running Keycloak Ingestor...")
        from backend.ingestion.keycloak_ingestor import KeycloakIngestor
        ingestor = KeycloakIngestor()
        data = ingestor.collect()
        logger.info(f"✅ Keycloak: {len(data.get('users', []))} users collected")
        return {"source": "keycloak", "users": len(data.get('users', []))}
    except Exception as e:
        logger.error(f"❌ Keycloak failed: {e}")
        return {"source": "keycloak", "error": str(e)}


def run_threat_intel_enricher():
    """Threat Intel — CVSS/EPSS/KEV enrichment"""
    try:
        logger.info("=" * 60)
        logger.info("🛡️ Running Threat Intel Enricher...")
        from backend.Enrichment.threat_intel import ThreatIntelEnricher
        enricher = ThreatIntelEnricher()
        count = enricher.enrich_database_findings()
        logger.info(f"✅ Threat Intel: {count} findings enriched")
        return {"source": "threat_intel", "enriched": count}
    except Exception as e:
        logger.error(f"❌ Threat Intel failed: {e}")
        return {"source": "threat_intel", "error": str(e)}


# ============================================================
# UNIFIED OUTPUT GENERATOR
# ============================================================

def fetch_unified_findings(business_context=None):
    """Fetch all findings in unified format with likelihood/impact/metadata"""
    from backend.database import db
    business_context = business_context or {}

    query = """
        SELECT 
            f.finding_id,
            f.asset_id,
            f.source,
            f.severity,
            f.title,
            f.description,
            f.cve_id,
            f.cvss_score,
            f.epss_score,
            f.cisa_kev,
            f.mitre_technique,
            f.raw_data,
            f.created_at,
            a.asset_name,
            a.asset_type,
            a.ip_address,
            a.hostname,
            a.environment,
            a.production_status,
            a.criticality,
            a.asset_value
        FROM findings f
        LEFT JOIN assets a ON f.asset_id = a.asset_id
        ORDER BY 
            CASE f.severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            f.created_at DESC
    """

    findings = db.execute_query(query)
    unified = []

    for f in findings:
        raw = parse_raw_data(f.get('raw_data'))

        # LIKELIHOOD
        likelihood = {
            "cvss_score": _safe_float(f.get('cvss_score'), default=5.0),
            "epss_score": _safe_float(f.get('epss_score'), default=0.1),
            "exploit_available": "Yes" if f.get('cisa_kev') else "No",
            "exploit_type": _safe_string(raw.get("exploit_type"), default="None"),
            "threat_actor": _safe_string(raw.get("threat_actor"), default="Unknown_Actor"),
            "malware": _safe_string(raw.get("malware"), default="No"),
            "mitre_technique": _safe_string(f.get('mitre_technique'), default="T0000"),
            "patched": "No",
            "mfa": "No",
            "waf": "No",
            "edr": "No",
        }

        # IMPACT
        impact = {
            "asset_name": _safe_string(f.get('asset_name') or business_context.get("asset_name"), default="Nexora Website"),
            "asset_type": _safe_string(f.get('asset_type') or business_context.get("asset_type"), default="web_application"),
            "business_unit": _safe_string(business_context.get("business_unit"), default="Digital Banking"),
            "asset_owner": _safe_string(business_context.get("asset_owner"), default="Alex Morgan"),
            "asset_value": _safe_float(business_context.get("business_value") or f.get('asset_value'), default=50000000.0),
            "downtime_cost_per_hour": _safe_float(business_context.get("downtime_cost"), default=250000.0),
            "recovery_cost": _safe_float(business_context.get("recovery_cost"), default=5000000.0),
            "criticality": int(_safe_float(f.get('criticality'), default=5.0)),
            "environment": _safe_string(f.get('environment'), default="production"),
            "production_status": _safe_string(f.get('production_status'), default="production"),
            "ip_address": _safe_string(f.get('ip_address'), default=NEXORA_IP),
            "hostname": _safe_string(f.get('hostname'), default="desktop-72ti05t.tailc1051b.ts.net"),
        }

        # METADATA
        created_at = f.get('created_at')
        age_days = None
        if created_at:
            try:
                age_days = (datetime.now() - created_at).days
            except Exception:
                age_days = None

        metadata = {
            "discovered_at": _safe_string(
                raw.get("@timestamp") or (created_at.isoformat() if created_at else None),
                default=datetime.now().isoformat()
            ),
            "source_tool": _safe_string(f.get('source'), default="unknown"),
            "finding_age_days": int(age_days) if age_days is not None else 0,
        }

        # FINAL FINDING
        finding = {
            "finding_id": f['finding_id'],
            "asset_id": f['asset_id'],
            "source": f['source'],
            "severity": _safe_string(f.get('severity'), default="info").lower(),
            "title": _safe_string(f.get('title'), default="Untitled Finding"),
            "description": _safe_string(f.get('description'), default="No description available"),
            "likelihood": likelihood,
            "impact": impact,
            "metadata": metadata,
            "detail": raw,
            "framework_tags": [],
            "remediation_cost": None,
            "risk_reduction": None,
            "risk_score": None,
            "sle": None,
            "aro": None,
            "ale": None,
        }
        unified.append(finding)

    return unified


def save_unified_output(findings, user_config=None):
    """Save unified findings to JSON file"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    user_config = user_config or {}

    output = {
        "generated_at": datetime.now().isoformat(),
        "scan_config": {
            "target_url": user_config.get("target_url", NEXORA_URL),
            "target_ip": NEXORA_IP,
            "business": user_config.get("business", {}),
        },
        "total_findings": len(findings),
        "findings": findings,
        "summary": {
            "by_source": {},
            "by_severity": {},
            "kev_count": 0,
            "cve_count": 0,
        }
    }

    for f in findings:
        src = f['source']
        sev = f['severity']

        output['summary']['by_source'][src] = output['summary']['by_source'].get(src, 0) + 1
        output['summary']['by_severity'][sev] = output['summary']['by_severity'].get(sev, 0) + 1

        if f['likelihood'].get('exploit_available') == "Yes":
            output['summary']['kev_count'] += 1
        if f['detail'].get('cve_id'):
            output['summary']['cve_count'] += 1

    latest_file = os.path.join(OUTPUT_DIR, 'latest.json')
    with open(latest_file, 'w', encoding='utf-8') as fp:
        json.dump(output, fp, indent=2, default=str)

    timestamped_file = os.path.join(OUTPUT_DIR, f'findings_{timestamp}.json')
    with open(timestamped_file, 'w', encoding='utf-8') as fp:
        json.dump(output, fp, indent=2, default=str)

    logger.info(f"✅ Saved: {latest_file}")
    logger.info(f"✅ Saved: {timestamped_file}")

    return latest_file


# ============================================================
# MAIN PIPELINE
# ============================================================

def main(target_url=None):
    """Run all ingestors and generate unified output"""
    print("\n" + "=" * 60)
    print("🚀 CyberFinGuard — Unified Ingestion Pipeline")
    print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")

    # ============================================================
    # LOAD USER CONFIG
    # ============================================================
    user_config = load_user_config()

    # Priority: CLI arg > user config > default Nexora
    if not target_url:
        target_url = user_config.get('target_url') or NEXORA_URL

    business_context = user_config.get('business', {})

    # ============================================================
    # EXTRACT HOSTNAME/IP
    # ============================================================
    hostname = target_url.replace("https://", "").replace("http://", "").split("/")[0]
    target_ip = get_ip_from_hostname(hostname)

    print(f"🎯 Target URL: {target_url}")
    print(f"🌐 Target IP:  {target_ip}")
    print(f"🏢 Business:   {business_context.get('asset_name', 'Nexora Website')}")
    print(f"   Unit:       {business_context.get('business_unit', 'Digital Banking')}")
    print(f"   Value:      ₹{business_context.get('business_value', '50000000')}")
    print()

    # ============================================================
    # RUN ALL INGESTORS
    # ============================================================
    results = {}

    # 1. ZAP — Manual scan (Nexora website)
    results['zap'] = run_zap_manual(target_url=target_url)

    # 2. Nmap — Nexora IP
    results['nmap'] = run_nmap(target=target_ip)

    # 3. Nuclei — Nexora website (all severities)
    results['nuclei'] = run_nuclei(
        target=target_url,
        severity='low,medium,high,critical'
    )

    # 4. Wazuh — Local Docker
    results['wazuh'] = run_wazuh()

    # 5. Prowler — AWS
    results['prowler'] = run_prowler()

    # 6. Keycloak — Local Docker (8090)
    results['keycloak'] = run_keycloak()

    # 7. Threat Intel — Enrich CVEs
    results['threat_intel'] = run_threat_intel_enricher()

    # ============================================================
    # SUMMARY
    # ============================================================
    print("\n" + "=" * 60)
    print("📊 INGESTION SUMMARY")
    print("=" * 60)

    for source, result in results.items():
        print(f"\n🔹 {source.upper()}:")
        if isinstance(result, dict):
            for key, value in result.items():
                print(f"   {key}: {value}")

    # ============================================================
    # UNIFIED OUTPUT
    # ============================================================
    print("\n" + "=" * 60)
    print("📋 GENERATING UNIFIED OUTPUT")
    print("=" * 60)

    findings = fetch_unified_findings(business_context=business_context)
    output_file = save_unified_output(findings, user_config=user_config)

    print(f"\n✅ Total findings: {len(findings)}")
    print(f"✅ Output file: {output_file}")
    print(f"\n📤 This file will be consumed by:")
    print(f"   1. Risk Quantification Model (SLE/ARO/ALE)")
    print(f"   2. Investment Optimization Model (Knapsack)")
    print(f"   3. CISO/CFO Dashboards")
    print(f"   4. AI Decision Layer (Chatbot/What-if)")

    print("\n" + "=" * 60)
    print(f"⏰ Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60 + "\n")

    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else None
    main(target_url=target)