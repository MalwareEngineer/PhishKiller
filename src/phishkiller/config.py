"""Application configuration via pydantic-settings."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="PK_",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "PhishKiller"
    debug: bool = False
    log_level: str = "INFO"

    # Database (async for FastAPI)
    database_url: str = (
        "postgresql+asyncpg://localhost:5432/phishkiller"
    )
    # Sync database URL for Celery workers
    sync_database_url: str = (
        "postgresql+psycopg2://localhost:5432/phishkiller"
    )
    database_pool_size: int = 20
    database_max_overflow: int = 10

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    redis_cache_ttl: int = 300

    # Celery
    celery_broker_url: str = "amqp://localhost:5672//"
    celery_result_backend: str = "redis://localhost:6379/1"

    # Analysis
    kit_download_dir: str = "./downloads"
    kit_extract_dir: str = "./extracted"
    max_kit_size_mb: int = 50
    download_timeout: int = 30
    tlsh_min_size: int = 50
    yara_rules_dir: str = "./rules"

    # Browser-based downloading (Camoufox stealth browser fallback)
    browser_download_enabled: bool = False
    browser_download_timeout: int = 60
    browser_render_on_thin_results: bool = True
    browser_dedup_tlsh_threshold: int = 30
    browser_render_max_variations: int = 20
    browser_render_pool_stop: int = 3  # consecutive TLSH dupes before stopping re-render loop

    # Chain crawling
    chain_max_depth: int = 5
    chain_max_children_per_kit: int = 10
    chain_link_score_threshold: float = 0.5
    chain_enabled: bool = True

    # Campaign auto-creation
    campaign_tlsh_threshold: int = 30

    # CORS
    cors_origins: list[str] = ["http://localhost:5173"]



@lru_cache
def get_settings() -> Settings:
    return Settings()
