import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

class Config:
    """Base application configuration."""
    SECRET_KEY = os.environ.get("SECRET_KEY", "fraud-detector-super-secret-key-2026")
    HOST = os.environ.get("HOST", "0.0.0.0")
    PORT = int(os.environ.get("PORT", 5000))
    DEBUG = os.environ.get("DEBUG", "false").lower() in ("true", "1", "yes")

    # ML Artifacts path
    ARTIFACTS_DIR = os.environ.get("ARTIFACTS_DIR", str(BASE_DIR / "model_artifacts"))
    
    # Optional threshold override (None uses model metadata recommended_threshold)
    THRESHOLD_OVERRIDE = float(os.environ["THRESHOLD_OVERRIDE"]) if "THRESHOLD_OVERRIDE" in os.environ else None
    
    # Database
    DATA_DIR = BASE_DIR / "data"
    DATABASE_PATH = os.environ.get("DATABASE_PATH", str(DATA_DIR / "url_fraud.db"))
    
    # Limits & Security
    MAX_BATCH_SIZE = int(os.environ.get("MAX_BATCH_SIZE", 500))
    CORS_ORIGINS = os.environ.get("CORS_ORIGINS", "*").split(",")
    LOG_LEVEL = os.environ.get("LOG_LEVEL", "INFO")
    
    # Rate limiting defaults
    RATE_LIMIT_ENABLED = os.environ.get("RATE_LIMIT_ENABLED", "false").lower() in ("true", "1", "yes")
