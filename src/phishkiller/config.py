"""Application configuration via pydantic-settings."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="PK_",
        case_sensitive=False,
    )

    # Application
    app_name: str = "PhishKiller"
    debug: bool = False
    log_level: str = "INFO"

    # Database (async for FastAPI)
    database_url: str = (
        "postgresql+asyncpg://phishkiller:phishkiller@localhost:5432/phishkiller"
    )
    # Sync database URL for Celery workers
    sync_database_url: str = (
        "postgresql+psycopg2://phishkiller:phishkiller@localhost:5432/phishkiller"
    )
    database_pool_size: int = 20
    database_max_overflow: int = 10

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    redis_cache_ttl: int = 300

    # Celery
    celery_broker_url: str = "amqp://guest:guest@localhost:5672//"
    celery_result_backend: str = "redis://localhost:6379/1"

    # Feed API keys
    phishtank_api_key: str = ""
    urlhaus_auth_key: str = ""

    # Analysis
    kit_download_dir: str = "./downloads"
    kit_extract_dir: str = "./extracted"
    max_kit_size_mb: int = 50
    download_timeout: int = 30
    tlsh_min_size: int = 50
    yara_rules_dir: str = "./rules"

    # CertStream
    certstream_url: str = "wss://certstream.calidog.io"
    certstream_score_threshold: int = 75
    certstream_suspicious_keywords: list[str] = [
        "login", "signin", "verify", "secure", "account",
        "update", "confirm", "banking", "paypal", "microsoft",
        "apple", "google", "amazon", "netflix",
    ]


@lru_cache
def get_settings() -> Settings:
    return Settings()
