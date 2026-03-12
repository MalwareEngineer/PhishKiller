"""Common Pydantic schemas used across the API."""

from pydantic import BaseModel


class PaginatedResponse(BaseModel):
    total: int
    offset: int
    limit: int


class MessageResponse(BaseModel):
    message: str


class HealthService(BaseModel):
    status: str
    detail: str | None = None


class HealthResponse(BaseModel):
    status: str
    services: dict[str, HealthService]
