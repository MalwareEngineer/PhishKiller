"""FastAPI application factory."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from darla.api.router import api_router
from darla.auth import (
    AuditLogMiddleware,
    DisabledAuthLoggingMiddleware,
    run_startup_guardrails,
)
from darla.config import get_settings
from darla.database import async_engine


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    yield
    await async_engine.dispose()


def create_app() -> FastAPI:
    settings = get_settings()

    # Auth guardrails (RFC §16) run BEFORE we build the app so a
    # misconfigured deployment fails-fast at process start, not at
    # first request.  ``SystemExit`` raised here propagates to uvicorn
    # → process exits with a clear log line.
    run_startup_guardrails(settings)

    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="Phishing kit tracking and analysis platform",
        lifespan=lifespan,
    )
    # Middleware order matters — Starlette runs middlewares in reverse
    # of registration (last added = outermost wrap = runs first on the
    # way in, last on the way out).  We want:
    #
    #   CORS (outermost)         — handle preflights without auth/audit
    #   AuditLog                 — capture every request, including 401s
    #   DisabledAuthLogging      — emits CRITICAL log per request in disabled mode
    #   <route handler>          — current_user dep runs here
    #
    # So registration order is: DisabledAuthLogging, AuditLog, CORS.
    app.add_middleware(DisabledAuthLoggingMiddleware)
    app.add_middleware(AuditLogMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
