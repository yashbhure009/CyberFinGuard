import sys
import os
import json
from collections.abc import Iterator
from urllib.parse import urlparse

# Path setup
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

import psycopg2
from psycopg2.extras import RealDictCursor
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

try:
    from backend.database import DatabaseUnavailableError, db
    from backend.models import (
        AssetResponse,
        BusinessContextCreate,
        CloudTargetCreate,
        IAMTargetCreate,
        NetworkTargetCreate,
        WebsiteTargetCreate,
        AIRecommendation,
        RiskRecommendationsRequest,
        AssistantQueryRequest,
    )
    from backend.repository import AssetRepository
except ModuleNotFoundError:
    from database import DatabaseUnavailableError, db
    from models import (
        AssetResponse,
        BusinessContextCreate,
        CloudTargetCreate,
        IAMTargetCreate,
        NetworkTargetCreate,
        WebsiteTargetCreate,
        AIRecommendation,
        RiskRecommendationsRequest,
        AssistantQueryRequest,
    )
    from repository import AssetRepository

app = FastAPI(title="CyberFinGuard API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "status": "ok",
        "service": "CyberFinGuard API",
        "version": "1.0.0",
        "docs": "/docs",
        "endpoints": {
            "health": "/health",
            "integrations": "/api/integrations",
            "findings": "/findings",
            "technical_dashboard": "/api/dashboard/technical"
        }
    }


def get_repository() -> Iterator[AssetRepository]:
    # TODO(auth): add the authenticated principal as a dependency here and scope queries to it.
    with db.connection() as connection:
        yield AssetRepository(connection)


@app.exception_handler(DatabaseUnavailableError)
async def database_unavailable(_: Request, exc: DatabaseUnavailableError) -> JSONResponse:
    return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content={"detail": str(exc)})


@app.exception_handler(psycopg2.OperationalError)
async def database_operational_error(_: Request, __: psycopg2.OperationalError) -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={"detail": "Database is temporarily unavailable"},
    )


def response(asset: dict, unmapped: list[str] | None = None) -> AssetResponse:
    return AssetResponse(**asset, unmapped_fields=unmapped or [])


from pydantic import BaseModel, Field

class ScanRequest(BaseModel):
    target: str
    scan_type: str = "quick"
    sources: list[str] = Field(default_factory=lambda: ["zap", "nmap", "nuclei"])


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/integrations")
@app.get("/api/integrations")
def integration_status():
    """Configuration status of supported security tools."""
    from backend.ingestion.common import configured
    return {
        "integrations": {
            "zap": {"configured": configured(os.getenv("ZAP_API_URL")), "mode": "api"},
            "nmap": {"configured": bool(os.getenv("NMAP_PATH")), "mode": "local_cli"},
            "nuclei": {"configured": bool(os.getenv("NUCLEI_PATH")), "mode": "local_cli"},
            "wazuh": {"configured": all(configured(os.getenv(k)) for k in ("WAZUH_API_URL", "WAZUH_USERNAME", "WAZUH_PASSWORD")), "mode": "api"},
            "prowler": {"configured": all(configured(os.getenv(k)) for k in ("KALI_HOST", "KALI_SSH_PASSWORD")), "mode": "ssh_cli"},
            "keycloak": {"configured": all(configured(os.getenv(k)) for k in ("KEYCLOAK_URL", "KEYCLOAK_PASSWORD")), "mode": "admin_api"},
            "threat_intel": {"configured": True, "mode": "public_api"},
        }
    }


@app.post("/integrations/{source}/collect")
@app.post("/api/integrations/{source}/collect")
def collect_integration(source: str):
    """Run non-targeted collection for wazuh, prowler, keycloak, threat_intel."""
    valid_sources = {"wazuh", "prowler", "keycloak", "threat_intel"}
    if source not in valid_sources:
        raise HTTPException(status_code=400, detail=f"Invalid integration '{source}'. Must be one of {valid_sources}")
    try:
        if source == "threat_intel":
            from backend.Enrichment.threat_intel import ThreatIntelEnricher
            return {"source": source, "enriched": ThreatIntelEnricher().enrich_database_findings()}
        elif source == "wazuh":
            from backend.ingestion.wazuh_ingestor import WazuhIngestor
            return WazuhIngestor().run()
        elif source == "prowler":
            from backend.ingestion.prowler_ingestor import ProwlerIngestor
            return ProwlerIngestor().run()
        elif source == "keycloak":
            from backend.ingestion.keycloak_ingestor import KeycloakIngestor
            return KeycloakIngestor().run()
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"{source} collection failed: {exc}") from exc


@app.post("/scan")
@app.post("/api/scan")
def start_scan(request: ScanRequest):
    """Run ZAP, Nmap, or Nuclei scan against authorized target."""
    target = (request.target or "").strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target is required.")
    
    from backend.ingestion.common import require_authorized_target
    try:
        require_authorized_target(target)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    results = {}
    if "zap" in request.sources:
        from backend.ingestion.zap_ingestor import ZAPIngestor
        results["zap"] = ZAPIngestor().run(target_url=target)
    if "nmap" in request.sources:
        from backend.ingestion.nmap_ingestor import NmapIngestor
        results["nmap"] = NmapIngestor().run(target=target)
    if "nuclei" in request.sources:
        from backend.ingestion.nuclei_ingestor import NucleiIngestor
        results["nuclei"] = NucleiIngestor().run(target=target)

    with db.connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT COUNT(*) AS count FROM findings")
            count = (cur.fetchone() or {}).get("count", 0)

    return {
        "status": "completed",
        "target": target,
        "findings_count": count,
        "results": results
    }


@app.get("/findings")
@app.get("/api/findings")
def get_findings(source: str | None = None, severity: str | None = None, limit: int = 100):
    """Fetch normalized findings from database."""
    query = "SELECT * FROM findings"
    params = []
    conditions = []
    if source:
        conditions.append("source = %s")
        params.append(source)
    if severity:
        conditions.append("severity = %s")
        params.append(severity)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY created_at DESC LIMIT %s"
    params.append(min(max(limit, 1), 500))

    with db.connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(query, tuple(params))
            findings = [dict(r) for r in cur.fetchall()]

    return {"count": len(findings), "findings": findings}


@app.get("/api/dashboard/technical")
@app.get("/dashboard/technical")
def get_technical_dashboard(repository: AssetRepository = Depends(get_repository)):
    """Return technical dashboard summary metrics and findings list."""
    return repository.get_technical_dashboard()


@app.post("/api/risk-analysis/recommendations")
def generate_recommendations(payload: RiskRecommendationsRequest) -> dict[str, object]:
    # OpenRouter exposes an OpenAI-compatible chat-completions API.
    # Keep OPENAI_API_KEY as a migration fallback for existing local setups.
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip() or os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key or api_key in {"your-key-here", "your-openrouter-key-here"}:
        raise HTTPException(status_code=503, detail="AI recommendations not configured")

    context = payload.findings_summary
    if payload.asset_id:
        with db.connection() as connection:
            context = AssetRepository(connection).get_risk_analysis_context(payload.asset_id)
        if context is None:
            raise HTTPException(status_code=404, detail="Asset not found")
    prompt = """Return a JSON object with a `recommendations` array of mitigation recommendation objects for this cybersecurity asset. Use only these keys in each item: control_name, description, risk_reduction, roi_estimate, priority. Keep risk_reduction as a percentage from 0 to 100, roi_estimate as a rough multiplier string, and priority as an integer from 1 (highest) to 5. These are ROUGH ORDER-OF-MAGNITUDE ESTIMATES based on general security investment patterns, not precise calculations. Do not fabricate an investment_cost or any currency amount because no real cost data is provided. Give one-sentence descriptions. Asset and finding context follows:\n""" + json.dumps(context or {}, default=str)
    try:
        from openai import APIConnectionError, APIError, APITimeoutError, AuthenticationError, OpenAI, RateLimitError
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="AI client is not installed") from exc

    try:
        base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").strip()
        default_headers = {
            "X-OpenRouter-Title": os.getenv("OPENROUTER_APP_TITLE", "CyberFinGuard"),
        }
        referer = os.getenv("OPENROUTER_HTTP_REFERER", "").strip()
        if referer:
            default_headers["HTTP-Referer"] = referer

        client = OpenAI(
            api_key=api_key,
            base_url=base_url,
            default_headers=default_headers,
            timeout=30.0,
        )
        completion = client.chat.completions.create(
            model=os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
            messages=[
                {"role": "system", "content": "You provide cautious, neutral cybersecurity mitigation estimates. Never claim precise financial calculations."},
                {"role": "user", "content": prompt},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
        )
    except AuthenticationError as exc:
        raise HTTPException(status_code=502, detail="AI provider authentication failed") from exc
    except RateLimitError as exc:
        raise HTTPException(status_code=502, detail="AI provider rate limit reached") from exc
    except APITimeoutError as exc:
        raise HTTPException(status_code=502, detail="AI provider request timed out") from exc
    except APIConnectionError as exc:
        raise HTTPException(status_code=502, detail="Unable to connect to AI provider") from exc
    except APIError as exc:
        raise HTTPException(status_code=502, detail="AI provider API error") from exc

    content = completion.choices[0].message.content if completion.choices else None
    try:
        parsed = json.loads(content or "")
        records = parsed if isinstance(parsed, list) else parsed.get("recommendations")
        recommendations = TypeAdapter(list[AIRecommendation]).validate_python(records)
    except (json.JSONDecodeError, TypeError, AttributeError, ValidationError) as exc:
        raise HTTPException(status_code=502, detail="AI provider returned invalid recommendation data") from exc
    return {"source": "ai", "recommendations": [recommendation.model_dump() for recommendation in recommendations]}


def _assistant_json_completion(messages: list[dict[str, str]]) -> dict[str, object]:
    """Call OpenRouter through the already-installed OpenAI-compatible SDK."""
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip() or os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key or api_key in {"your-key-here", "your-openrouter-key-here"}:
        raise HTTPException(status_code=503, detail="AI assistant not configured")
    try:
        from openai import APIConnectionError, APIError, APITimeoutError, AuthenticationError, OpenAI, RateLimitError
    except ImportError as exc:
        raise HTTPException(status_code=503, detail="AI client is not installed") from exc

    try:
        client = OpenAI(
            api_key=api_key,
            base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").strip(),
            default_headers={"X-OpenRouter-Title": os.getenv("OPENROUTER_APP_TITLE", "CyberFinGuard")},
            timeout=30.0,
        )
        completion = client.chat.completions.create(
            model=os.getenv("OPENROUTER_MODEL", "openai/gpt-4o-mini"),
            messages=messages,
            response_format={"type": "json_object"},
            temperature=0.2,
        )
    except AuthenticationError as exc:
        raise HTTPException(status_code=502, detail="AI provider authentication failed") from exc
    except RateLimitError as exc:
        raise HTTPException(status_code=502, detail="AI provider rate limit reached") from exc
    except APITimeoutError as exc:
        raise HTTPException(status_code=502, detail="AI provider request timed out") from exc
    except APIConnectionError as exc:
        raise HTTPException(status_code=502, detail="Unable to connect to AI provider") from exc
    except APIError as exc:
        raise HTTPException(status_code=502, detail="AI provider API error") from exc

    try:
        parsed = json.loads(completion.choices[0].message.content or "") if completion.choices else None
        if not isinstance(parsed, dict):
            raise ValueError("Expected a JSON object")
        return parsed
    except (json.JSONDecodeError, TypeError, ValueError, AttributeError) as exc:
        raise HTTPException(status_code=502, detail="AI provider returned malformed JSON") from exc


def _assistant_context() -> dict[str, object]:
    with db.connection() as connection:
        return AssetRepository(connection).get_assistant_context()


def _simulate_scenario(context: dict[str, object], scenario_type: str, params: dict[str, object]) -> dict[str, object]:
    baseline = context.get("total_ale")
    assets = context.get("simulation_assets", [])
    assumptions: list[str]
    simulated = baseline if isinstance(baseline, (int, float)) else None

    if scenario_type == "enforce_mfa":
        scope = params.get("scope", "all_assets")
        privileged = scope == "all_privileged"
        affected = [asset for asset in assets if not asset.get("mfa_enabled") and (not privileged or (asset.get("criticality") or 0) >= 4)]
        affected_ale = sum(float(asset.get("ale") or 0) for asset in affected)
        # Illustrative assumption: closing an MFA gap reduces the affected ALE contribution by 25%.
        assumptions = ["Illustrative only; not the real risk engine.", "Affected assets are those with mfa_enabled=false.", "all_privileged means criticality 4 or 5.", "Assumes a flat 25% reduction to affected ALE contribution."]
        if simulated is not None:
            simulated = max(0, simulated - affected_ale * 0.25)
        summary = f"Enforcing MFA for {scope.replace('_', ' ')} would affect {len(affected)} currently unprotected asset(s) under the stated assumption."
    elif scenario_type == "delay_remediation":
        try:
            days = max(0, float(params.get("days", 0)))
        except (TypeError, ValueError):
            days = 0
        unpatched_ale = sum(float(asset.get("ale") or 0) for asset in assets if asset.get("patching_status") == "unpatched")
        # Illustrative assumption: unpatched ALE contribution increases linearly by 1% per 30 days.
        increase = days / 30 * 0.01
        assumptions = ["Illustrative only; not the real risk engine.", "Only assets marked patching_status=unpatched are affected.", "Assumes a linear 1% increase to unpatched ALE contribution per 30-day delay."]
        if simulated is not None:
            simulated = baseline + unpatched_ale * increase
        summary = f"Delaying remediation by {days:g} day(s) increases the unpatched contribution under the stated linear assumption."
    else:
        result = _assistant_json_completion([
            {"role": "system", "content": "You are a cautious what-if assistant. Use only the supplied data context. State assumptions plainly, give directional illustrative reasoning only, never present a precise calculated figure, and remind the user this is a discussion aid, not a decision-grade number. Return JSON with scenarioSummary, baselineAle, simulatedAle, deltaPercent, and assumptions."},
            {"role": "user", "content": json.dumps({"data_context": context, "question": params.get("question", "")}, default=str)},
        ])
        result["isIllustrative"] = True
        result.setdefault("assumptions", ["Illustrative discussion aid based on the supplied data context; not a decision-grade calculation."])
        return result

    delta = ((simulated - baseline) / baseline * 100) if isinstance(baseline, (int, float)) and baseline else None
    return {"scenarioSummary": summary, "baselineAle": baseline, "simulatedAle": simulated, "deltaPercent": delta, "assumptions": assumptions, "isIllustrative": True}


@app.post("/api/assistant/query")
def assistant_query(payload: AssistantQueryRequest) -> dict[str, object]:
    api_key = os.getenv("OPENROUTER_API_KEY", "").strip() or os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key or api_key in {"your-key-here", "your-openrouter-key-here"}:
        raise HTTPException(status_code=503, detail="AI assistant not configured")
    context = _assistant_context()
    if payload.mode == "simulate":
        scenario = payload.scenario
        if scenario and scenario.type in {"enforce_mfa", "delay_remediation"}:
            return _simulate_scenario(context, scenario.type, scenario.params)
        scenario_params = dict(scenario.params) if scenario else {}
        scenario_params["question"] = payload.question
        return _simulate_scenario(context, scenario.type if scenario else "free_text", scenario_params)

    result = _assistant_json_completion([
        {"role": "system", "content": "You are CyberRobo, a helpful cybersecurity and financial cyber-risk assistant. Answer general cybersecurity, IAM, vulnerability, controls, and risk-management questions using your general knowledge. For definitions, acronyms, and concept questions such as 'What is EPSS?', answer the definition directly and concisely from general knowledge first; do not refuse or lead with missing dashboard data. When a question asks about this organization's specific assets, findings, controls, coverage, or risk scores, use only the supplied CyberFinGuard data context: cite the specific figures used, say 'not yet calculated' for pending or missing risk_scores values, and never invent organization-specific numbers. If a question mixes general and organization-specific parts, answer the general part and clearly label any organization-specific limitation. For IAM questions, use iam_setup_status and assets_by_type: explain that missing IAM representation means identity-access coverage cannot be verified, and distinguish that dataset limitation from proof that every IAM control is absent. Return JSON with answer and groundedIn, where groundedIn is an array of the data points or general knowledge basis actually used."},
        {"role": "user", "content": json.dumps({"data_context": context, "question": payload.question}, default=str)},
    ])
    answer = result.get("answer")
    grounded_in = result.get("groundedIn")
    if not isinstance(answer, str) or not isinstance(grounded_in, list) or not all(isinstance(item, str) for item in grounded_in):
        raise HTTPException(status_code=502, detail="AI provider returned an invalid assistant response")
    return {"answer": answer, "groundedIn": grounded_in}


def _update_scan_config(target_url=None, cloud=None, identity=None, business=None):
    scan_config_path = os.path.join(ROOT_DIR, 'scan_config.json')
    current = {}
    if os.path.exists(scan_config_path):
        try:
            with open(scan_config_path, 'r', encoding='utf-8') as fp:
                current = json.load(fp)
        except Exception:
            current = {}
    if target_url:
        current['target_url'] = target_url
    if cloud:
        current['cloud'] = {**current.get('cloud', {}), **cloud}
    if identity:
        current['identity'] = {**current.get('identity', {}), **identity}
    if business:
        clean_biz = {}
        for k, v in business.items():
            if hasattr(v, 'as_tuple') or hasattr(v, '__float__'):
                try:
                    clean_biz[k] = float(v)
                except (ValueError, TypeError):
                    clean_biz[k] = str(v)
            else:
                clean_biz[k] = v
        current['business'] = {**current.get('business', {}), **clean_biz}
    try:
        with open(scan_config_path, 'w', encoding='utf-8') as fp:
            json.dump(current, fp, indent=2, default=str)
    except Exception as exc:
        logger.warning(f"Failed to save scan_config.json: {exc}")


@app.post("/api/assets/website", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_website(payload: WebsiteTargetCreate, repository: AssetRepository = Depends(get_repository)) -> AssetResponse:
    parsed = urlparse(str(payload.url))
    asset = repository.create({
        "asset_name": parsed.hostname,
        "asset_type": "website",
        "hostname": parsed.hostname,
        "environment": "unknown",
        "internet_exposed": True,
        "production_status": "unknown",
    })
    _update_scan_config(target_url=str(payload.url))
    return response(asset, ["url"])


@app.post("/api/assets/network", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_network(payload: NetworkTargetCreate, repository: AssetRepository = Depends(get_repository)) -> AssetResponse:
    ip_address = str(payload.ip_address)
    asset = repository.create({
        "asset_name": ip_address,
        "asset_type": "network_target",
        "ip_address": ip_address,
        "environment": "unknown",
        "internet_exposed": False,
        "production_status": "unknown",
    })
    return response(asset, ["port"])


@app.post("/api/assets/cloud", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_cloud(payload: CloudTargetCreate, repository: AssetRepository = Depends(get_repository)) -> AssetResponse:
    asset = repository.create({
        "asset_name": f"{payload.provider} cloud account",
        "asset_type": "cloud_account",
        "application": payload.provider,
        "environment": "unknown",
        "internet_exposed": False,
        "production_status": "unknown",
    })
    _update_scan_config(cloud={"provider": payload.provider, "fields": payload.fields})
    return response(asset, [f"fields.{key}" for key in payload.fields])


@app.post("/api/assets/iam", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_iam(payload: IAMTargetCreate, repository: AssetRepository = Depends(get_repository)) -> AssetResponse:
    parsed = urlparse(str(payload.url))
    asset = repository.create({
        "asset_name": f"Keycloak {payload.realm}",
        "asset_type": "iam",
        "hostname": parsed.hostname,
        "application": "Keycloak",
        "environment": "unknown",
        "internet_exposed": False,
        "production_status": "unknown",
    })
    _update_scan_config(identity={"url": str(payload.url), "realm": payload.realm, "client_id": payload.client_id})
    return response(asset, ["url", "realm", "clientId", "clientSecret"])


@app.post("/api/assets/business-context", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
def create_business_context(payload: BusinessContextCreate, repository: AssetRepository = Depends(get_repository)) -> AssetResponse:
    asset = repository.create({
        "asset_name": payload.asset_name,
        "asset_type": payload.asset_type,
        "business_unit": payload.business_unit,
        "owner": payload.asset_owner,
        "environment": "unknown",
        "internet_exposed": False,
        "production_status": "unknown",
        "criticality": payload.asset_criticality,
        "data_type": payload.data_sensitivity,
        "dependencies": [payload.service_dependency],
        "asset_value": payload.business_value,
    })
    _update_scan_config(business={
        "asset_name": payload.asset_name,
        "asset_type": payload.asset_type,
        "business_unit": payload.business_unit,
        "asset_owner": payload.asset_owner,
        "business_value": payload.business_value,
        "downtime_cost": payload.downtime_cost_per_hour,
        "recovery_cost": payload.recovery_cost
    })
    return response(asset, [
        "operationalCriticality",
        "downtimeCostPerHour",
        "regulatoryExposure",
        "recoveryCost",
        "revenueDependency",
    ])


@app.get("/api/assets/{asset_id}", response_model=AssetResponse)
def get_asset(asset_id: str, repository: AssetRepository = Depends(get_repository)) -> AssetResponse:
    asset = repository.get(asset_id)
    if asset is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return response(asset)
