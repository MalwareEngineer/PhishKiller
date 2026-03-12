"""Health check endpoints."""

from fastapi import APIRouter

from phishkiller.api.deps import DbSession
from phishkiller.schemas.common import HealthResponse, HealthService

router = APIRouter()


@router.get("", response_model=HealthResponse)
async def health_check(db: DbSession) -> HealthResponse:
    services: dict[str, HealthService] = {}

    # Check database
    try:
        from sqlalchemy import text

        await db.execute(text("SELECT 1"))
        services["database"] = HealthService(status="ok")
    except Exception as e:
        services["database"] = HealthService(status="error", detail=str(e))

    # Check Redis
    try:
        import redis as redis_lib

        from phishkiller.config import get_settings

        settings = get_settings()
        r = redis_lib.from_url(settings.redis_url)
        r.ping()
        services["redis"] = HealthService(status="ok")
    except Exception as e:
        services["redis"] = HealthService(status="error", detail=str(e))

    overall = "ok" if all(s.status == "ok" for s in services.values()) else "degraded"
    return HealthResponse(status=overall, services=services)
