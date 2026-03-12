"""Database engine and session management for both async (FastAPI) and sync (Celery) contexts."""

from collections.abc import AsyncGenerator

from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import Session, sessionmaker

from phishkiller.config import get_settings

settings = get_settings()

# --- Async engine (for FastAPI) ---
async_engine = create_async_engine(
    settings.database_url,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    echo=settings.debug,
)

async_session_factory = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


# --- Sync engine (for Celery workers) ---
sync_engine = create_engine(
    settings.sync_database_url,
    pool_size=settings.database_pool_size,
    max_overflow=settings.database_max_overflow,
    echo=settings.debug,
)

sync_session_factory = sessionmaker(
    sync_engine,
    class_=Session,
    expire_on_commit=False,
)


def get_sync_db() -> Session:
    """Get a sync database session for use in Celery tasks."""
    return sync_session_factory()
