"""Audit logging middleware — RFC 0001 Phase 5.

Writes one row to ``audit_log`` per HTTP request (method, path, status,
latency, requesting user, request_id, optional per-route ``extra``).
Runs after every handler, regardless of success or failure.

Design contract:

* **Audit failure never breaks the request.**  If the DB is briefly
  unreachable, we log the failure and serve the response anyway.  A
  missing audit row is recoverable; a 500 served because audit broke
  is not.
* **The middleware uses its own DB session.**  The request's handler
  may have its session rolled back on error; the audit row still needs
  to land.  We open a fresh session against the same async engine.
* **High-volume noise paths are skipped.**  ``/api/v1/health`` is hit
  every few seconds by the load balancer.  Logging those would dwarf
  every other entry.  Anything skipped here is invisible to incident
  response — keep the skiplist tiny.
* **request_id is generated here and returned to the client via the
  ``X-Request-ID`` response header.**  Quoting it in a support
  request lets ops grep audit_log directly.
* **Disabled-mode requests still write rows** with
  ``actor_subject=NULL`` and ``auth_mode='disabled'``.  See RFC §16.1
  — the community/local-eval deployment still has a complete request
  audit trail.
* **Failed-auth requests (401 before ``current_user`` resolved any
  identity) write rows** with the default auth_mode populated here
  and NULL actor.  An anonymous attacker probing the API still leaves
  fingerprints.

Per-route ``extra`` data is set by handlers via :func:`set_audit_extra`
— e.g. victim-PII routes record the victim_ids returned for "who saw
which victims" reports (RFC §5.2).
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import Any

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

from darla.config import get_settings
from darla.database import async_session_factory
from darla.models import AUTH_MODE_DISABLED, AUTH_MODE_OIDC, AuditLog

logger = logging.getLogger(__name__)


# Paths whose requests are *not* written to audit_log.  Keep this set
# tiny — anything here is invisible to incident response.  Currently
# only the anonymous health probe, which fires every few seconds from
# the load balancer.  The analyst-gated ``/health/detail`` is NOT
# skipped (operator-driven, low volume, worth tracking).
_SKIP_PATHS: frozenset[str] = frozenset({
    "/api/v1/health",
})


def set_audit_extra(request: Request, **kwargs: Any) -> None:
    """Attach per-route extra audit data to ``request.state``.

    The middleware reads ``request.state.audit_extra`` after the
    handler returns and persists it in :attr:`AuditLog.extra` (a JSONB
    column).  Multiple calls within one request *merge* keys — call it
    incrementally as the handler discovers what's worth logging.

    Example (in a victim-list handler)::

        items = await service.list_victims(...)
        set_audit_extra(request, victim_ids=[str(v.id) for v in items])

    Values must be JSON-serializable (str, int, list/dict thereof,
    bool, None).  Non-serializable values are silently dropped at
    write time by Postgres' JSONB serializer to keep the audit path
    forgiving — but log warnings during dev would help catch this;
    for now we trust the caller.
    """
    existing = getattr(request.state, "audit_extra", None)
    if existing is None:
        request.state.audit_extra = dict(kwargs)
    else:
        existing.update(kwargs)


class AuditLogMiddleware(BaseHTTPMiddleware):
    """Per-request audit row writer.  See module docstring for design."""

    async def dispatch(self, request: Request, call_next):
        # Skip high-volume noise paths (currently just /health).
        # Note: this happens BEFORE we initialize request.state — anything
        # the handler might need from state (e.g. request_id) is also
        # skipped, which is intentional for these no-audit paths.
        if request.url.path in _SKIP_PATHS:
            return await call_next(request)

        settings = get_settings()
        request_id = str(uuid.uuid4())

        # Initialize request.state slots up-front.  The ``current_user``
        # dependency (auth middleware) may overwrite auth_mode /
        # actor_subject / actor_upn before the handler runs — but if
        # the request 401s in current_user, those overwrites never
        # happen and we fall back to these defaults.
        request.state.request_id = request_id
        request.state.audit_extra = None
        request.state.auth_mode = (
            AUTH_MODE_OIDC if settings.auth_enabled else AUTH_MODE_DISABLED
        )
        request.state.actor_subject = None
        request.state.actor_upn = None

        start = time.monotonic()
        response = None
        status_code = 500  # assume the worst until we know better
        try:
            response = await call_next(request)
            status_code = response.status_code
        finally:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            # Write the audit row regardless of success or exception.
            # The handler may have raised — we still want the row.
            await self._write_audit_row(
                request, status_code, elapsed_ms, request_id,
            )

        # Attach the request_id to the response so client-side error
        # messages can quote it.  ``response`` is None only if
        # ``call_next`` raised, in which case Starlette/FastAPI will
        # build its own 500 response upstream — we couldn't have set
        # the header anyway.
        if response is not None:
            response.headers["X-Request-ID"] = request_id
        return response

    async def _write_audit_row(
        self,
        request: Request,
        status_code: int,
        elapsed_ms: int,
        request_id: str,
    ) -> None:
        """Persist one audit_log row.  Swallows exceptions by design."""
        try:
            row = AuditLog(
                actor_subject=getattr(request.state, "actor_subject", None),
                actor_upn=getattr(request.state, "actor_upn", None),
                auth_mode=getattr(
                    request.state, "auth_mode", AUTH_MODE_OIDC,
                ),
                method=request.method,
                # ``url.path`` is the actual request path (no query
                # string).  Query strings are excluded by RFC §5.2 —
                # they can carry tokens or PII we don't want in the
                # audit stream.
                path=request.url.path,
                status_code=status_code,
                response_ms=elapsed_ms,
                request_id=request_id,
                extra=getattr(request.state, "audit_extra", None),
            )
            async with async_session_factory() as session:
                session.add(row)
                await session.commit()
        except Exception as e:
            # Audit failure must not break the request.  Log loudly
            # so ops notices if it becomes persistent.
            logger.exception(
                "audit_log write failed (request_id=%s, path=%s): %s",
                request_id, request.url.path, e,
            )
