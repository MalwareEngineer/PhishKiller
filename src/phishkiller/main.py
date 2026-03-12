"""FastAPI application factory."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from phishkiller.api.router import api_router
from phishkiller.config import get_settings
from phishkiller.database import async_engine


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    yield
    await async_engine.dispose()


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="0.1.0",
        description="Phishing kit tracking and analysis platform",
        lifespan=lifespan,
    )
    app.include_router(api_router, prefix="/api/v1")
    return app


app = create_app()
