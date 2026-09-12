from datetime import datetime
from decimal import Decimal
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, IPvAnyAddress, SecretStr


class APIModel(BaseModel):
    model_config = ConfigDict(alias_generator=lambda value: "".join(
        word if index == 0 else word.capitalize()
        for index, word in enumerate(value.split("_"))
    ), populate_by_name=True)


class WebsiteTargetCreate(APIModel):
    url: HttpUrl


class NetworkTargetCreate(APIModel):
    ip_address: IPvAnyAddress
    port: Annotated[int, Field(ge=1, le=65535)]


class CloudTargetCreate(APIModel):
    provider: Literal["AWS", "Azure", "GCP"]
    fields: dict[str, str]


class IAMTargetCreate(APIModel):
    url: HttpUrl
    realm: Annotated[str, Field(min_length=1, max_length=255)]
    client_id: Annotated[str, Field(min_length=1, max_length=255)]
    client_secret: SecretStr


class BusinessContextCreate(APIModel):
    asset_name: Annotated[str, Field(min_length=1, max_length=255)]
    asset_type: Annotated[str, Field(min_length=1, max_length=50)]
    business_unit: Annotated[str, Field(min_length=1, max_length=100)]
    asset_owner: Annotated[str, Field(min_length=1, max_length=100)]
    business_value: Annotated[Decimal, Field(ge=0, max_digits=15, decimal_places=2)]
    operational_criticality: Annotated[int, Field(ge=1, le=5)]
    data_sensitivity: Annotated[str, Field(min_length=1, max_length=50)]
    service_dependency: Annotated[str, Field(min_length=1)]
    downtime_cost_per_hour: Annotated[Decimal, Field(ge=0)]
    regulatory_exposure: Annotated[Decimal, Field(ge=0)]
    recovery_cost: Annotated[Decimal, Field(ge=0)]
    revenue_dependency: Annotated[Decimal, Field(ge=0, le=100)]
    asset_criticality: Annotated[int, Field(ge=1, le=5)]


class AssetResponse(APIModel):
    asset_id: str
    asset_name: str
    asset_type: str
    ip_address: str | None = None
    hostname: str | None = None
    application: str | None = None
    business_unit: str | None = None
    owner: str | None = None
    environment: str | None = None
    internet_exposed: bool
    production_status: str | None = None
    criticality: int | None = None
    data_type: str | None = None
    dependencies: list[str] | None = None
    asset_value: Decimal | None = None
    discovered_at: datetime
    updated_at: datetime
    unmapped_fields: list[str] = Field(default_factory=list)
