"""
CyberFinGuard — FastAPI Backend
Exposes ingestion + risk data to frontend
"""

import os
import sys
import logging
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from database import db

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
    target: str
    scan_type: str = "quick"  # quick, full
    sources: list = ["zap", "nmap", "nuclei"]


class FindingResponse(BaseModel):
    finding_id: str
    asset_id: str
    source: str
    title: str
    severity: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None


# ============================================================
# ENDPOINTS
# ============================================================

@app.get("/")
def root():
    return {"status": "ok", "service": "CyberFinGuard API"}


@app.get("/health")
def health():
    return {"status": "healthy", "timestamp": datetime.now().isoformat()}


@app.post("/scan")
def start_scan(request: ScanRequest):
    """Frontend se scan trigger karo"""
    logger.info(f"🚀 Scan request: {request.target} | Type: {request.scan_type}")
    
    results = {}
    
    # ZAP scan
    if "zap" in request.sources:
        try:
            from ingestion.zap_ingestor import ZAPIngestor
            zap = ZAPIngestor()
            results["zap"] = zap.run(target_url=request.target)
        except Exception as e:
            results["zap"] = {"error": str(e)}
    
    # Nmap scan
    if "nmap" in request.sources:
        try:
            from ingestion.nmap_ingestor import NmapIngestor
            nmap = NmapIngestor()
            results["nmap"] = nmap.run(target=request.target)
        except Exception as e:
            results["nmap"] = {"error": str(e)}
    
    # Nuclei scan
    if "nuclei" in request.sources:
        try:
            from ingestion.nuclei_ingestor import NucleiIngestor
            nuclei = NucleiIngestor()
            results["nuclei"] = nuclei.run(target=request.target)
        except Exception as e:
            results["nuclei"] = {"error": str(e)}
    
    return {
        "status": "completed",
        "target": request.target,
        "results": results
    }


@app.get("/findings")
def get_findings(source: Optional[str] = None, limit: int = 100):
    """Sab findings laao"""
    query = "SELECT * FROM findings"
    params = []
    
    if source:
        query += " WHERE source = %s"
        params.append(source)
    
    query += " ORDER BY created_at DESC LIMIT %s"
    params.append(limit)
    
    findings = db.execute_query(query, tuple(params))
    return {"count": len(findings), "findings": findings}


@app.get("/assets")
def get_assets():
    """Sab assets laao"""
    assets = db.execute_query("SELECT * FROM assets ORDER BY asset_name")
    return {"count": len(assets), "assets": assets}


@app.get("/risk-summary")
def get_risk_summary():
    """Risk summary — frontend dashboard ke liye"""
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
        
        sle = asset_value * (cvss / 10)
        aro = 0.5 if cvss > 7 else 0.2
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
    findings = db.execute_query("SELECT COUNT(*) as count FROM findings")
    assets = db.execute_query("SELECT COUNT(*) as count FROM assets")
    
    return {
        "total_findings": findings[0]['count'] if findings else 0,
        "total_assets": assets[0]['count'] if assets else 0
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)