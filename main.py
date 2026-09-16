"""
CyberFinGuard — Unified Ingestion Runner
Outputs unified findings JSON for downstream models
With user-config integration (website, cloud, identity, business context)
"""

import os
import sys
import json
import logging
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

# User config file (written by API from frontend form)
SCAN_CONFIG_PATH = os.path.join(ROOT_DIR, 'scan_config.json')


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
    """Safely parse raw_data (can be str, dict, or None)"""
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


def _detect_patched(raw):
    if raw.get("patched") is not None:
        return "Yes" if raw["patched"] else "No"
    if raw.get("patch_status"):
        return raw["patch_status"]
    return "Unknown"


def _detect_mfa(raw):
    if raw.get("mfa") is not None:
        return "Yes" if raw["mfa"] else "No"
    if raw.get("mfa_enabled") is not None:
        return "Yes" if raw["mfa_enabled"] else "No"
    if raw.get("totp") is not None:
        return "Yes" if raw["totp"] else "No"
    return "Unknown"


def _detect_waf(raw):
    if raw.get("waf") is not None:
        return "Yes" if raw["waf"] else "No"
    if raw.get("waf_enabled") is not None:
        return "Yes" if raw["waf_enabled"] else "No"
    return "Unknown"


def _detect_edr(raw):
    if raw.get("edr") is not None:
        return "Yes" if raw["edr"] else "No"
    if raw.get("edr_enabled") is not None:
        return "Yes" if raw["edr_enabled"] else "No"
    return "Unknown"


# ============================================================
# INGESTOR RUNNERS
# ============================================================

def run_zap(target=None):
    try:
        logger.info("=" * 60)
        logger.info("🕷️ Running ZAP Ingestor...")
        from backend.ingestion.zap_ingestor import ZAPIngestor
        ingestor = ZAPIngestor()
        result = ingestor.run(target_url=target)
        logger.info(f"✅ ZAP: {result}")
        return result
    except Exception as e:
        logger.error(f"❌ ZAP failed: {e}")
        return {"source": "zap", "error": str(e)}


def run_nmap(target='scanme.nmap.org'):
    try:
        logger.info("=" * 60)
        logger.info("🔍 Running Nmap Ingestor...")
        from backend.ingestion.nmap_ingestor import NmapIngestor
        ingestor = NmapIngestor()
        result = ingestor.run(target=target)
        logger.info(f"✅ Nmap: {result}")
        return result
    except Exception as e:
        logger.error(f"❌ Nmap failed: {e}")
        return {"source": "nmap", "error": str(e)}


def run_nuclei(target='https://httpbin.org'):
    try:
        logger.info("=" * 60)
        logger.info("🎯 Running Nuclei Ingestor...")
        from backend.ingestion.nuclei_ingestor import NucleiIngestor
        ingestor = NucleiIngestor()
        result = ingestor.run(target=target)
        logger.info(f"✅ Nuclei: {result}")
        return result
    except Exception as e:
        logger.error(f"❌ Nuclei failed: {e}")
        return {"source": "nuclei", "error": str(e)}


def run_wazuh():
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

        # ====================================================
        # LIKELIHOOD
        # ====================================================
        likelihood = {
            "cvss_score": _safe_float(f.get('cvss_score'), default=5.0),
            "epss_score": _safe_float(f.get('epss_score'), default=0.1),
            "exploit_available": _safe_string(
                "Yes" if f.get('cisa_kev') else raw.get("exploit_available"),
                default="No"
            ),
            "exploit_type": _safe_string(raw.get("exploit_type"), default="None"),
            "threat_actor": _safe_string(raw.get("threat_actor"), default="Unknown_Actor"),
            "malware": _safe_string(raw.get("malware"), default="No"),
            "mitre_technique": _safe_string(f.get('mitre_technique'), default="T0000"),
            "patched": _safe_string(_detect_patched(raw), default="No"),
            "mfa": _safe_string(_detect_mfa(raw), default="No"),
            "waf": _safe_string(_detect_waf(raw), default="No"),
            "edr": _safe_string(_detect_edr(raw), default="No"),
        }

        # ====================================================
        # IMPACT — user business context overrides DB values
        # ====================================================
        def _pick(user_key, db_key, cast=None):
            """Prefer user-provided value over DB value."""
            user_val = business_context.get(user_key)
            if user_val not in (None, "", "0"):
                try:
                    return cast(user_val) if cast else user_val
                except (ValueError, TypeError):
                    return user_val
            db_val = f.get(db_key)
            if db_val is None:
                return None
            try:
                return cast(db_val) if cast else db_val
            except (ValueError, TypeError):
                return db_val

        impact = {
            "asset_name": _safe_string(_pick("asset_name", "asset_name"), default="Unknown_Asset"),
            "asset_type": _safe_string(_pick("asset_type", "asset_type"), default="unknown"),
            "business_unit": _safe_string(business_context.get("business_unit"), default="unknown"),
            "asset_owner": _safe_string(business_context.get("asset_owner"), default="unknown"),
            "asset_value": _safe_float(
                business_context.get("business_value") or f.get('asset_value'),
                default=1000000.0
            ),
            "downtime_cost_per_hour": _safe_float(business_context.get("downtime_cost"), default=0.0),
            "recovery_cost": _safe_float(business_context.get("recovery_cost"), default=0.0),
            "criticality": int(_safe_float(f.get('criticality'), default=3.0)),
            "environment": _safe_string(f.get('environment'), default="unknown"),
            "production_status": _safe_string(f.get('production_status'), default="unknown"),
            "ip_address": _safe_string(f.get('ip_address'), default="0.0.0.0"),
            "hostname": _safe_string(f.get('hostname'), default="unknown-host"),
            "data_classification": _safe_string(raw.get("data_classification"), default="internal"),
            "compliance_scope": raw.get("compliance_scope") or [],
        }

        # ====================================================
        # METADATA
        # ====================================================
        created_at = f.get('created_at')
        age_days = None
        if created_at:
            try:
                age_days = (datetime.now() - created_at).days
            except Exception:
                age_days = None

        _now = datetime.now().isoformat()
        metadata = {
            "discovered_at": _safe_string(
                raw.get("@timestamp") or (created_at.isoformat() if created_at else None),
                default=_now
            ),
            "created_at": _safe_string(
                created_at.isoformat() if created_at else None,
                default=_now
            ),
            "updated_at": _safe_string(
                raw.get("updated_at") or (created_at.isoformat() if created_at else None),
                default=_now
            ),
            "source_tool": _safe_string(f.get('source'), default="unknown"),
            "source_version": _safe_string(
                raw.get("version") or raw.get("rule", {}).get("version"),
                default="unknown"
            ),
            "scan_id": _safe_string(
                raw.get("scan_id") or raw.get("id"),
                default="no-scan-id"
            ),
            "finding_age_days": int(age_days) if age_days is not None else 0,
        }

        # ====================================================
        # FINAL FINDING
        # ====================================================
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

            # Model placeholders
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
    """Save unified findings to JSON file for downstream models"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    user_config = user_config or {}

    output = {
        "generated_at": datetime.now().isoformat(),
        "scan_config": {
            "target_url": user_config.get("target_url"),
            "cloud": user_config.get("cloud", {}),
            "identity": {
                # Never write client_secret to output
                "url": user_config.get("identity", {}).get("url"),
                "realm": user_config.get("identity", {}).get("realm"),
                "client_id": user_config.get("identity", {}).get("client_id"),
            },
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

    # ============================================
    # LOAD USER CONFIG
    # ============================================
    user_config = load_user_config()

    # Override target_url from config if not given via CLI
    if not target_url and user_config.get('target_url'):
        target_url = user_config['target_url']

    business_context = user_config.get('business', {})

    print(f"🎯 Target URL: {target_url}")
    print(f"🏢 Business context: {business_context}")
    print()

    # ============================================
    # RUN ALL INGESTORS
    # ============================================
    results = {}

    results['zap'] = run_zap(target=target_url)
    results['nmap'] = run_nmap(target='scanme.nmap.org')
    results['nuclei'] = run_nuclei(target=target_url or 'https://httpbin.org')
    results['wazuh'] = run_wazuh()
    results['prowler'] = run_prowler()
    results['keycloak'] = run_keycloak()
    results['threat_intel'] = run_threat_intel_enricher()

    print("\n" + "=" * 60)
    print("📊 INGESTION SUMMARY")
    print("=" * 60)

    for source, result in results.items():
        print(f"\n🔹 {source.upper()}:")
        if isinstance(result, dict):
            for key, value in result.items():
                print(f"   {key}: {value}")

    print("\n" + "=" * 60)
    print("📋 GENERATING UNIFIED OUTPUT FOR DOWNSTREAM MODELS")
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