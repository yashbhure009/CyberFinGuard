"""
CyberFinGuard — Unified Ingestion Runner
Outputs unified findings JSON for downstream models
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


# ============================================================
# HELPER FUNCTIONS
# ============================================================

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
        from backend.ingestion.prowler_ingestor import ProwlerIngestor, ProwlerConfig
        config = ProwlerConfig()
        ingestor = ProwlerIngestor(config)
        result = ingestor.run()
        logger.info(f"✅ Prowler: {result}")
        return result
    except Exception as e:
        logger.error(f"❌ Prowler failed: {e}")
        return {"source": "prowler", "error": str(e)}


def run_keycloak():
    try:
        logger.info("=" * 60)
        logger.info("🔐 Running Keycloak Ingestor...")
        from backend.ingestion.keycloak_ingestor import KeycloakIngestor
        ingestor = KeycloakIngestor()
        ingestor.connect_ssh()
        data = ingestor.collect()
        ingestor.close()
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

def fetch_unified_findings():
    """Fetch all findings in unified format"""
    from backend.database import db
    
    query = """
        SELECT 
            finding_id,
            asset_id,
            source,
            severity,
            title,
            description,
            cve_id,
            cvss_score,
            epss_score,
            cisa_kev,
            mitre_technique,
            raw_data,
            created_at
        FROM findings
        ORDER BY 
            CASE severity
                WHEN 'critical' THEN 1
                WHEN 'high' THEN 2
                WHEN 'medium' THEN 3
                WHEN 'low' THEN 4
                ELSE 5
            END,
            created_at DESC
    """
    
    findings = db.execute_query(query)
    
    unified = []
    for f in findings:
        finding = {
            # CORE IDENTIFIERS
            "finding_id": f['finding_id'],
            "asset_id": f['asset_id'],
            "source": f['source'],
            "severity": f['severity'],
            
            # FINDING DETAILS
            "title": f['title'],
            "description": f['description'],
            
            # THREAT INTEL
            "cve_id": f['cve_id'],
            "cvss_score": float(f['cvss_score']) if f['cvss_score'] else None,
            "epss_score": float(f['epss_score']) if f['epss_score'] else None,
            "cisa_kev": bool(f['cisa_kev']),
            
            # MITRE
            "mitre_technique": f['mitre_technique'],
            
            # METADATA
            "timestamp": f['created_at'].isoformat() if f['created_at'] else None,
            "detail": parse_raw_data(f['raw_data']),
            "framework_tags": []
        }
        unified.append(finding)
    
    return unified


def save_unified_output(findings):
    """Save unified findings to JSON file for downstream models"""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    output = {
        "generated_at": datetime.now().isoformat(),
        "total_findings": len(findings),
        "findings": findings,
        "summary": {
            "by_source": {},
            "by_severity": {},
            "kev_count": 0,
            "cve_count": 0,
        }
    }
    
    # Calculate summary
    for f in findings:
        src = f['source']
        sev = f['severity']
        
        output['summary']['by_source'][src] = output['summary']['by_source'].get(src, 0) + 1
        output['summary']['by_severity'][sev] = output['summary']['by_severity'].get(sev, 0) + 1
        
        if f['cisa_kev']:
            output['summary']['kev_count'] += 1
        if f['cve_id']:
            output['summary']['cve_count'] += 1
    
    # Save latest
    latest_file = os.path.join(OUTPUT_DIR, 'latest.json')
    with open(latest_file, 'w', encoding='utf-8') as fp:
        json.dump(output, fp, indent=2, default=str)
    
    # Save timestamped
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
    
    results = {}
    
    # ============================================================
    # 1. LOCAL SCAN TOOLS
    # ============================================================
    results['zap'] = run_zap(target=target_url)
    results['nmap'] = run_nmap(target='scanme.nmap.org')
    results['nuclei'] = run_nuclei(target=target_url or 'https://httpbin.org')
    
    # ============================================================
    # 2. TEAMMATES' TOOLS (Uncomment if accessible)
    # ============================================================
    results['wazuh'] = run_wazuh()
    results['prowler'] = run_prowler()
    results['keycloak'] = run_keycloak()
    
    # ============================================================
    # 3. ENRICHMENT
    # ============================================================
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
    print("📋 GENERATING UNIFIED OUTPUT FOR DOWNSTREAM MODELS")
    print("=" * 60)
    
    findings = fetch_unified_findings()
    output_file = save_unified_output(findings)
    
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