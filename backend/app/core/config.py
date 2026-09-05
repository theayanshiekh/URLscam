from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]
PROJECT_ROOT = BACKEND_ROOT.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(PROJECT_ROOT / ".env"),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "PhishGuard AI"
    app_env: str = "development"
    debug: bool = False
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    database_url: str = f"sqlite:///{(BACKEND_ROOT / 'data' / 'phishguard.db').as_posix()}"
    admin_api_key: str = ""

    rate_limit_per_minute: int = 30
    batch_max_urls: int = 200
    batch_max_bytes: int = 1_048_576

    dns_timeout: float = 2.0
    tls_timeout: float = 3.0
    intel_timeout: float = 4.0
    enable_redirect_analysis: bool = False

    virustotal_api_key: str = ""
    google_safe_browsing_key: str = ""
    urlhaus_enabled: bool = False

    model_path: str = str(PROJECT_ROOT / "ml" / "models" / "phishguard_model.joblib")
    metrics_path: str = str(PROJECT_ROOT / "ml" / "evaluation" / "metrics.json")
    feature_importance_path: str = str(PROJECT_ROOT / "ml" / "evaluation" / "feature_importance.json")

    threshold_low: int = 29
    threshold_medium: int = 59
    threshold_high: int = 79

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
