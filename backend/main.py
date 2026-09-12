import os
from collections.abc import Iterator
from urllib.parse import urlparse

import psycopg2
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.database import DatabaseUnavailableError, db
from backend.models import (
    AssetResponse,
    BusinessContextCreate,
    CloudTargetCreate,
    IAMTargetCreate,
    NetworkTargetCreate,
    WebsiteTargetCreate,
)
from backend.repository import AssetRepository

app = FastAPI(title="CyberFinGuard API", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


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


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


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

