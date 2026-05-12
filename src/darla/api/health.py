"""Health check endpoints.

Two-mode behaviour driven by ``auth_enabled`` (RFC §16 guardrail #5,
§17.4):

* **Auth disabled** — endpoint always returns HTTP 503 with an empty
  body.  Production load balancers (ALB/ECS) consequently refuse to
  route traffic to a disabled-mode container; overriding the
  healthcheck to accept it requires a separate, conscious infra
  change.  Empty body so an anonymous caller learns nothing about
  the deployment beyond "this isn't healthy."
* **Auth enabled** — returns the legacy detailed body (DB + Redis
  status) for backwards compatibility.  Phase 4 will split this into
  an anonymous 200/503-only endpoint plus an analyst-gated detail
  endpoint, per RFC §17.4 non-disclosure.
"""

from fastapi import APIRouter, Response, status

from darla.api.deps import DbSession
from darla.config import get_settings
from darla.schemas.common import HealthResponse, HealthService

router = APIRouter()


@router.get(
    "",
    response_model=HealthResponse | None,
    responses={503: {"description": "Disabled-mode (auth off) — empty body"}},
)
async def health_check(db: DbSession, response: Response):
    settings = get_settings()
    if not settings.auth_enabled:
        # Disabled-mode guardrail — refuse the LB.  Empty body, no JSON,
        # no headers that disclose auth state.
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return Response(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)

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

        r = redis_lib.from_url(settings.redis_url)
        r.ping()
        services["redis"] = HealthService(status="ok")
    except Exception as e:
        services["redis"] = HealthService(status="error", detail=str(e))

    overall = "ok" if all(s.status == "ok" for s in services.values()) else "degraded"
    return HealthResponse(status=overall, services=services)
