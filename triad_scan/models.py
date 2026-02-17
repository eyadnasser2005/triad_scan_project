from pydantic import BaseModel, Field, ConfigDict
from typing import Optional


class AssetBase(BaseModel):
    cpe_string: str = Field(..., min_length=3, description="CPE 2.3 string identifying software/hardware")
    confidentiality: int = Field(..., ge=1, le=10)
    integrity: int = Field(..., ge=1, le=10)
    availability: int = Field(..., ge=1, le=10)


class AssetCreate(AssetBase):
    pass


class AssetRead(AssetBase):
    model_config = ConfigDict(from_attributes=True)
    id: int


class VulnerabilityBase(BaseModel):
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,}$")
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    is_known_exploited: bool = Field(default=False)


class VulnerabilityCreate(VulnerabilityBase):
    pass


class VulnerabilityRead(VulnerabilityBase):
    model_config = ConfigDict(from_attributes=True)
    id: int
