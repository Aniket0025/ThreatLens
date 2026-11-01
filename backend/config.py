"""
config.py — Centralised configuration for URLShield backend.
All runtime-tunable values are read from environment variables with safe defaults.
Copy .env.example to .env and edit before running.
"""

import os
from dotenv import load_dotenv

load_dotenv()  # loads .env if present; silently skips if absent


class Config:
    # Flask
    DEBUG: bool = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "change-me-in-production")

    # Paths
    MODEL_PATH: str = os.environ.get("MODEL_PATH", "url_model.pkl")
    DATASET_PATH: str = os.environ.get("DATASET_PATH", "../dataset/phishing_urls.csv")
    METRICS_PATH: str = os.environ.get("METRICS_PATH", "model_metrics.json")

    # CORS
    ALLOWED_ORIGINS: str = os.environ.get("ALLOWED_ORIGINS", "*")

    # Rate limiting (Flask-Limiter syntax)
    RATE_LIMIT_DEFAULT: str = os.environ.get("RATE_LIMIT_DEFAULT", "200 per day")
    RATE_LIMIT_PREDICT: str = os.environ.get("RATE_LIMIT_PREDICT", "60 per minute")

    # Logging
    LOG_LEVEL: str = os.environ.get("LOG_LEVEL", "INFO")

    # API
    API_VERSION: str = "v1"
