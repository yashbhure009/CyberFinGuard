from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from backend.database import DatabaseUnavailableError
from backend.main import app, get_repository


class FakeRepository:
    def __init__(self) -> None:
        self.created: list[dict] = []

    def create(self, values: dict) -> dict:
        self.created.append(values)
        now = datetime.now(timezone.utc)
        return {
            "asset_id": "AST-TEST0000001",
            "asset_name": values["asset_name"],
            "asset_type": values["asset_type"],
            "ip_address": values.get("ip_address"),
            "hostname": values.get("hostname"),
            "application": values.get("application"),
            "business_unit": values.get("business_unit"),
            "owner": values.get("owner"),
            "environment": values.get("environment"),
            "internet_exposed": values.get("internet_exposed", False),
            "production_status": values.get("production_status"),
            "criticality": values.get("criticality"),
            "data_type": values.get("data_type"),
            "dependencies": values.get("dependencies"),
            "asset_value": values.get("asset_value"),
            "discovered_at": now,
            "updated_at": now,
        }

    def get(self, asset_id: str) -> dict | None:
        return None


@pytest.fixture
def fake_repository() -> FakeRepository:
    return FakeRepository()


@pytest.fixture
def client(fake_repository: FakeRepository) -> TestClient:
    app.dependency_overrides[get_repository] = lambda: fake_repository
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_create_website_asset(client: TestClient, fake_repository: FakeRepository) -> None:
    result = client.post("/api/assets/website", json={"url": "https://example.com/payments"})

    assert result.status_code == 201
    assert result.json()["assetId"] == "AST-TEST0000001"
    assert result.json()["hostname"] == "example.com"
    assert result.json()["unmappedFields"] == ["url"]
    assert fake_repository.created[0]["asset_type"] == "website"


def test_network_validation_failure(client: TestClient) -> None:
    result = client.post("/api/assets/network", json={"ipAddress": "not-an-ip", "port": 70000})

    assert result.status_code == 422
    assert isinstance(result.json()["detail"], list)


def test_database_unavailable_returns_503() -> None:
    def unavailable_repository() -> None:
        raise DatabaseUnavailableError("Database is temporarily unavailable")

    app.dependency_overrides[get_repository] = unavailable_repository
    try:
        with TestClient(app, raise_server_exceptions=False) as test_client:
            result = test_client.post("/api/assets/website", json={"url": "https://example.com"})
    finally:
        app.dependency_overrides.clear()

    assert result.status_code == 503
    assert result.json() == {"detail": "Database is temporarily unavailable"}
