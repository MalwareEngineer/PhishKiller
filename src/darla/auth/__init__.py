"""Authentication & authorization for Darla — RFC 0001 Phase 2.

The public surface is intentionally small:

* :func:`current_user` — FastAPI dependency that validates the bearer
  JWT (when auth is enabled) and returns the corresponding
  :class:`darla.models.User`, or ``None`` when auth is disabled.
* :func:`require_role` — dependency factory that enforces a minimum
  :class:`darla.models.UserRole` on the caller.  No-op in disabled mode.
* :func:`run_startup_guardrails` — must be called once at app startup;
  refuses to start if disabled-mode is configured anywhere that looks
  like production (RFC §16).
* :class:`DisabledAuthLoggingMiddleware` — ASGI middleware that emits a
  CRITICAL log line per request when auth is disabled (RFC §16
  guardrail #6).

The middleware is wired up by :func:`darla.main.create_app`; nothing in
this package mutates global state at import time.
"""

from darla.auth.audit import AuditLogMiddleware, set_audit_extra
from darla.auth.guardrails import run_startup_guardrails
from darla.auth.middleware import (
    DisabledAuthLoggingMiddleware,
    current_user,
    require_role,
)

__all__ = [
    "AuditLogMiddleware",
    "DisabledAuthLoggingMiddleware",
    "current_user",
    "require_role",
    "run_startup_guardrails",
    "set_audit_extra",
]
