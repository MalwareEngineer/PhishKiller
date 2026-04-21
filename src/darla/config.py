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
    app_name: str = "Darla"
    debug: bool = False
    log_level: str = "INFO"

    # Database (async for FastAPI)
    database_url: str = (
        "postgresql+asyncpg://localhost:5432/darla"
    )
    # Sync database URL for Celery workers
    sync_database_url: str = (
        "postgresql+psycopg2://localhost:5432/darla"
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
    browser_turnstile_timeout: int = 30  # seconds before retrying Turnstile with fresh context
    browser_render_on_thin_results: bool = True
    browser_dedup_tlsh_threshold: int = 30
    browser_render_max_variations: int = 50
    browser_render_pool_stop: int = 3  # consecutive TLSH dupes before stopping re-render loop

    # Polymorphism detection
    browser_polymorphism_min_variants: int = 2      # min unique siblings on same domain
    browser_polymorphism_tlsh_max_distance: int = 200  # above this = unrelated, not polymorphic

    # External JS fetching (follow <script src="..."> in rendered pages)
    external_js_fetch_enabled: bool = True
    external_js_fetch_timeout: int = 15        # per-request timeout (seconds)
    external_js_fetch_max_depth: int = 2       # recursive JS→JS following depth
    external_js_fetch_max_files: int = 10      # max files to fetch per kit
    external_js_fetch_max_size_kb: int = 512   # max individual JS file size

    # Passive artifact rendering (EML / SVG / PDF / DOCX → _screenshots)
    artifact_render_enabled: bool = True

    # Active SVG execution — detonates SVG attachments with JS enabled and
    # captures all outbound network requests.  Goal: one-shot capture of the
    # full attacker infrastructure chain (SVG → remote loader → landing
    # page) without a second manual kit resubmission.  Terminal URLs feed
    # the chain crawler so child kits spawn automatically.
    svg_active_exec_enabled: bool = True
    svg_active_exec_timeout: int = 30        # per-SVG wall-clock budget (sec)
    svg_active_exec_max_requests: int = 200  # cap per SVG
    svg_active_exec_max_per_kit: int = 3     # at most N SVGs per kit get detonated

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
