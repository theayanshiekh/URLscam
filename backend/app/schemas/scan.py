from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

Classification = Literal["legitimate", "suspicious", "phishing"]
ThreatLevel = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]
Severity = Literal["positive", "low", "medium", "high", "critical"]


class AnalyzeRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=4096)
    demo: bool = False

    @field_validator("url")
    @classmethod
    def strip_url(cls, v: str) -> str:
        return v.strip()


class BatchAnalyzeRequest(BaseModel):
    urls: list[str] = Field(..., min_length=1, max_length=200)


class RiskFactorOut(BaseModel):
    name: str
    severity: str
    score: float
    explanation: str
    evidence: str = ""
    what_it_means: str = ""
    why_it_matters: str = ""
    what_to_do: str = ""


class UrlBreakdown(BaseModel):
    scheme: str | None = None
    username: str | None = None
    hostname: str | None = None
    port: int | None = None
    path: str | None = None
    query: str | None = None
    fragment: str | None = None
    registrable_domain: str | None = None
    subdomains: list[str] = Field(default_factory=list)
    tld: str | None = None
    is_ip: bool = False
    punycode: bool = False
    suspicious_components: list[str] = Field(default_factory=list)


class AnalyzeResponse(BaseModel):
    id: int | None = None
    url: str
    normalized_url: str
    classification: Classification
    risk_score: int
    confidence: float
    threat_level: ThreatLevel
    summary: str
    recommendation: str
    features: dict[str, Any]
    risk_factors: list[RiskFactorOut]
    url_breakdown: UrlBreakdown
    analysis_sources: list[str]
    ml: dict[str, Any] = Field(default_factory=dict)
    intel: dict[str, Any] = Field(default_factory=dict)
    https_note: str
    confidence_note: str
    demo: bool = False
    created_at: datetime | None = None
    stages: list[str] = Field(default_factory=list)


class HistoryItem(BaseModel):
    id: int
    url: str
    classification: str
    risk_score: int
    confidence: float
    threat_level: str
    created_at: datetime
    demo: bool = False


class HistoryList(BaseModel):
    items: list[HistoryItem]
    total: int
    page: int
    page_size: int


class HealthResponse(BaseModel):
    status: str
    app: str
    model_loaded: bool
    database: str
    redirect_analysis: str
    external_intel: dict[str, bool]


class ConfigResponse(BaseModel):
    app_name: str
    thresholds: dict[str, int]
    redirect_analysis_enabled: bool
    external_services: dict[str, bool]
    notes: list[str]
