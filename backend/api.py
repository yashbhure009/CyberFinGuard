"""
CyberFinGuard — FastAPI Backend
Frontend se input lene ke liye
"""

import os
import sys
import json
import logging
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

# Path setup
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

load_dotenv()
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="CyberFinGuard API",
    description="AI-Powered Cyber Risk Quantification Platform",
    version="1.0.0"
)

# CORS — frontend ko access dene ke liye
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# MODELS
# ============================================================

class ScanRequest(BaseModel):
    target: str  # URL ya IP address
    scan_type: str = "quick"  # quick, full
    sources: list = ["zap", "nmap", "nuclei"]  # kaunse tools chalane hain


class ScanResponse(BaseModel):
    status: str
    target: str
    findings_count: int
    findings: list


# ============================================================
# ENDPOINTS
# ============================================================

@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "CyberFinGuard API",
        "version": "1.0.0"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }


@app.post("/scan")
def start_scan(request: ScanRequest):
    """
    Frontend se scan trigger karo
    Input: {target: "https://example.com"}
    """
    logger.info(f"🚀 Scan request: {request.target} | Type: {request.scan_type}")
    
    # Validate target
    if not request.target:
        raise HTTPException(status_code=400, detail="Target is required")
    
    target = request.target.strip()
    
    results = {}
    
    # 1. ZAP Scan
    if "zap" in request.sources:
        try:
            logger.info("🕷️ Running ZAP...")
            from ingestion.zap_ingestor import ZAPIngestor
            zap = ZAPIngestor()
            results["zap"] = zap.run(target_url=target)
        except Exception as e:
            logger.error(f"❌ ZAP failed: {e}")
            results["zap"] = {"error": str(e)}
    
    # 2. Nmap Scan
    if "nmap" in request.sources:
        try:
            logger.info("🔍 Running Nmap...")
            from ingestion.nmap_ingestor import NmapIngestor
            nmap = NmapIngestor()
            # IP nikalo URL se
            nmap_target = target.replace("https://", "").replace("http://", "").split("/")[0]
            results["nmap"] = nmap.run(target=nmap_target)
        except Exception as e:
            logger.error(f"❌ Nmap failed: {e}")
            results["nmap"] = {"error": str(e)}
    
    # 3. Nuclei Scan
    if "nuclei" in request.sources:
        try:
            logger.info("🎯 Running Nuclei...")
            from ingestion.nuclei_ingestor import NucleiIngestor
            nuclei = NucleiIngestor()
            results["nuclei"] = nuclei.run(target=target)
        except Exception as e:
            logger.error(f"❌ Nuclei failed: {e}")
            results["nuclei"] = {"error": str(e)}
    
    # 4. Threat Intel Enrichment
    try:
        logger.info("🛡️ Running Threat Intel...")
        from Enrichment.threat_intel import ThreatIntelEnricher
        enricher = ThreatIntelEnricher()
        results["threat_intel"] = enricher.enrich_database_findings()
    except Exception as e:
        logger.error(f"❌ Threat Intel failed: {e}")
        results["threat_intel"] = {"error": str(e)}
    
    # Get findings count
    from database import db
    findings = db.execute_query("SELECT * FROM findings ORDER BY created_at DESC LIMIT 50")
    
    return {
        "status": "completed",
        "target": target,
        "findings_count": len(findings),
        "results": results,
        "findings": findings
    }


@app.get("/findings")
def get_findings(source: Optional[str] = None, limit: int = 100):
    """Sab findings laao"""
    from database import db
    
    query = "SELECT * FROM findings"
    params = []
    
    if source:
        query += " WHERE source = %s"
        params.append(source)
    
    query += " ORDER BY created_at DESC LIMIT %s"
    params.append(limit)
    
    findings = db.execute_query(query, tuple(params))
    return {
        "count": len(findings),
        "findings": findings
    }


@app.get("/assets")
def get_assets():
    """Sab assets laao"""
    from database import db
    assets = db.execute_query("SELECT * FROM assets ORDER BY asset_name")
    return {
        "count": len(assets),
        "assets": assets
    }


@app.get("/risk-summary")
def get_risk_summary():
    """Risk summary — frontend dashboard ke liye"""
    from database import db
    
    findings = db.execute_query("SELECT * FROM findings")
    assets = db.execute_query("SELECT * FROM assets")
    
    # Total risk calculate karo
    total_risk = 0
    for finding in findings:
        cvss = finding.get('cvss_score') or 5.0
        asset_id = finding.get('asset_id')
        asset_value = 10000000  # Default ₹1 Cr
        
        # Find asset value
        for asset in assets:
            if asset['asset_id'] == asset_id:
                asset_value = float(asset.get('asset_value') or 10000000)
                break
        
        sle = asset_value * (float(cvss) / 10)
        aro = 0.5 if float(cvss) > 7 else 0.2
        total_risk += sle * aro
    
    # Findings by severity
    severity_counts = {}
    for finding in findings:
        sev = finding.get('severity', 'info')
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    
    # Findings by source
    source_counts = {}
    for finding in findings:
        src = finding.get('source', 'unknown')
        source_counts[src] = source_counts.get(src, 0) + 1
    
    return {
        "total_findings": len(findings),
        "total_assets": len(assets),
        "total_risk_inr": total_risk,
        "severity_distribution": severity_counts,
        "source_distribution": source_counts,
        "timestamp": datetime.now().isoformat()
    }


@app.get("/stats")
def get_stats():
    """Quick stats"""
    from database import db
    findings = db.execute_query("SELECT COUNT(*) as count FROM findings")
    assets = db.execute_query("SELECT COUNT(*) as count FROM assets")
    
    return {
        "total_findings": findings[0]['count'] if findings else 0,
        "total_assets": assets[0]['count'] if assets else 0
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)