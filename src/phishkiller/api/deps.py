"""Shared FastAPI dependencies."""

from typing import Annotated

from fastapi import Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from phishkiller.database import get_db

DbSession = Annotated[AsyncSession, Depends(get_db)]


class PaginationParams:
    def __init__(
        self,
        offset: int = Query(0, ge=0, description="Number of items to skip"),
        limit: int = Query(50, ge=1, le=500, description="Number of items to return"),
    ):
        self.offset = offset
        self.limit = limit


Pagination = Annotated[PaginationParams, Depends()]
