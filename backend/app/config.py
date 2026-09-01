import os
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyHttpUrl, field_validator
from typing import List


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App ───────────────────────────────────────────────────────────
    ENVIRONMENT: str = "development"
    APP_NAME: str = "NewsMon"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    LOG_LEVEL: str = "info"

    # ── API ───────────────────────────────────────────────────────────
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    CORS_ORIGINS: List[str] = ["http://localhost:3000"]

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def parse_cors(cls, v):
        if isinstance(v, str):
            return [i.strip() for i in v.split(",")]
        return v

    # ── JWT ───────────────────────────────────────────────────────────
    JWT_SECRET_KEY: str = "change-me-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ── MongoDB ───────────────────────────────────────────────────────
    MONGODB_URL: str = "mongodb://localhost:27017"
    MONGODB_DB_NAME: str = "newsmon"

    # ── Elasticsearch ─────────────────────────────────────────────────
    ELASTICSEARCH_URL: str = "http://localhost:9200"
    ELASTICSEARCH_INDEX_PREFIX: str = "newsmon"

    # ── Redis ─────────────────────────────────────────────────────────
    REDIS_URL: str = "redis://localhost:6379/0"
    CELERY_BROKER_URL: str = "redis://localhost:6379/1"
    CELERY_RESULT_BACKEND: str = "redis://localhost:6379/2"

    # ── Microsoft Teams Webhooks ───────────────────────────────────────
    TEAMS_WEBHOOK_URL: str = ""
    TEAMS_WEBHOOK_URL_CYBER_PULSE: str = ""
    CYBER_PULSE_WEBHOOK_URL: str = ""
    TEAMS_WEBHOOK_URL_INDIAN_BASED: str = ""
    TEAMS_WEBHOOK_URL_GCC_MIDDLE_EAST: str = ""
    TEAMS_WEBHOOK_URL_HIGH_PRIORITY_NEWS: str = ""
    TEAMS_WEBHOOK_URL_DAILY_DIGEST: str = ""
    TEAMS_WEBHOOK_URL_INDIAN_BREACHES: str = ""
    TEAMS_WEBHOOK_URL_MIDDLE_EAST_COMPANIES: str = ""

    # ── CyberPulse Viral News Engine Settings ──────────────────────────
    CYBERPULSE_MIN_SOURCES: int = 2
    CYBERPULSE_HIGH_SOURCES: int = 10
    CYBERPULSE_TIME_WINDOW_HOURS: int = 72
    CYBERPULSE_SIMILARITY_THRESHOLD: float = 0.55
    CYBERPULSE_ALERT_DEDUPLICATION: bool = True

    # ── OpenAI ────────────────────────────────────────────────────────
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4.1"
    OPENAI_MAX_TOKENS: int = 8000
    OPENAI_TEMPERATURE: float = 0.1

    # ── NVIDIA NIM API ────────────────────────────────────────────────
    # Embedding key (nemotron-3-embed-1b) — also used for chat completions on NIM
    NVIDIA_API_KEY: str = ""
    # Reranking key (rerank-qa-mistral-4b)
    NVIDIA_RERANK_API_KEY: str = ""
    NVIDIA_BASE_URL: str = "https://integrate.api.nvidia.com/v1"
    NVIDIA_EMBED_MODEL: str = "nvidia/nemotron-3-embed-1b"
    NVIDIA_RERANK_MODEL: str = "nvidia/rerank-qa-mistral-4b"
    # Chat completions model for CTI classification
    NVIDIA_CHAT_MODEL: str = "meta/llama-3.1-8b-instruct"

    # ── MinIO / S3 ────────────────────────────────────────────────────
    MINIO_ENDPOINT: str = "localhost:9000"
    MINIO_ACCESS_KEY: str = "minioadmin"
    MINIO_SECRET_KEY: str = "minioadmin"
    MINIO_BUCKET_NAME: str = "newsmon"
    MINIO_USE_SSL: bool = False

    # ── Email ─────────────────────────────────────────────────────────
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    EMAIL_FROM: str = "noreply@newsmon.io"
    EMAIL_FROM_NAME: str = "NewsMon"

    # ── External APIs ─────────────────────────────────────────────────
    CISA_KEV_URL: str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    NVD_API_KEY: str = ""
    EPSS_API_URL: str = "https://api.first.org/data/v1/epss"
    VIRUSTOTAL_API_KEY: str = ""
    ABUSEIPDB_API_KEY: str = ""

    # ── Rate Limiting ─────────────────────────────────────────────────
    RATE_LIMIT_DEFAULT: int = 1000
    RATE_LIMIT_WINDOW_SECONDS: int = 3600
    RATE_LIMIT_LENS: int = 10

    # ── File Upload ───────────────────────────────────────────────────
    MAX_UPLOAD_SIZE_MB: int = 50
    ALLOWED_UPLOAD_TYPES: List[str] = ["pdf", "txt", "md", "html", "json"]

    # ── Sentry ────────────────────────────────────────────────────────
    SENTRY_DSN: str = ""

    # ── Admin Seed ────────────────────────────────────────────────────
    ADMIN_EMAIL: str = "admin@newsmon.io"
    ADMIN_PASSWORD: str = "ChangeMe123!"
    ADMIN_NAME: str = "Platform Admin"

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == "production"

    @property
    def is_development(self) -> bool:
        return self.ENVIRONMENT == "development"


@lru_cache()
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
