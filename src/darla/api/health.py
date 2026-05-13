"""Health check endpoints.

Two routes (RFC 0001 §16 guardrail #5, §17.4):

* **``GET /health``** — anonymous, non-disclosing.  Returns HTTP 200
  with an empty body when the service is up and auth is enabled, or
  HTTP 503 with an empty body when auth is *disabled* (load
  balancers refuse to route traffic to a disabled-mode container).
  Critically, this endpoint **never reveals** whether auth is enabled,
  what version is running, what services are healthy, or any other
  operational detail to anonymous callers.  An attacker scanning the
  internet learns only "this responds" or "this doesn't."

* **``GET /health/detail``** — analyst-gated.  Returns the full DB /
  Redis / etc. status JSON that ops needs for triage.  Only reachable
  with a valid analyst token, and only when auth is enabled (in
  disabled mode the route still works for any caller because
  ``require_role`` is a no-op then, but that's fine since the
  guardrails force localhost-only bind).
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from darla.api.deps import DbSession
from darla.auth import require_role
from darla.config import get_settings
from darla.models import User, UserRole
from darla.schemas.common import HealthResponse, HealthService

router = APIRouter()


@router.get("", status_code=status.HTTP_200_OK)
async def health_check() -> Response:
    """Anonymous, non-disclosing liveness probe.

    Implementation notes:

    * No DB / Redis call here.  A passing health check just means the
      process is alive and the gate-keeping policy says it should
      accept traffic.  Liveness is intentionally cheap.
    * No JSON body, no headers leaking auth state.  Load balancers
      only need the status code.
    * Disabled-mode → 503 (the guardrail).  Note that the disabled-
      mode response is INDISTINGUISHABLE from a generic "service
      unhealthy" 503 — anonymous probes can't tell why.
    """
    settings = get_settings()
    if not settings.auth_enabled:
        return Response(status_code=status.HTTP_503_SERVICE_UNAVAILABLE)
    return Response(status_code=status.HTTP_200_OK)


@router.get("/detail", response_model=HealthResponse)
async def health_detail(
    db: DbSession,
    user: Annotated[User | None, Depends(require_role(UserRole.ANALYST))],
) -> HealthResponse:
    """Detailed service status — DB + Redis + per-service breakdown.

    Analyst-gated because the response reveals deployment shape (which
    services run, error messages from internal probes) that's useful
    to an attacker.  In disabled mode this is reachable without a
    token, which is fine because the §16 localhost-only bind guardrail
    keeps it off the network.
    """
    del user  # accepted only to enforce role gate

    settings = get_settings()
    services: dict[str, HealthService] = {}

    try:
        from sqlalchemy import text

        await db.execute(text("SELECT 1"))
        services["database"] = HealthService(status="ok")
    except Exception as e:
        services["database"] = HealthService(status="error", detail=str(e))

    try:
        import redis as redis_lib

        r = redis_lib.from_url(settings.redis_url)
        r.ping()
        services["redis"] = HealthService(status="ok")
    except Exception as e:
        services["redis"] = HealthService(status="error", detail=str(e))

    overall = "ok" if all(s.status == "ok" for s in services.values()) else "degraded"
    return HealthResponse(status=overall, services=services)
