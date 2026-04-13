"""Pydantic schemas for the PhishDiff comparison API."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel


class DiffableKit(BaseModel):
    """Compact kit representation used in pair listings."""

    id: uuid.UUID
    source_url: str
    tlsh: str | None
    file_size: int | None
    status: str
    created_at: datetime


class DiffablePair(BaseModel):
    """A kit that can be diffed against a reference kit."""

    id: uuid.UUID
    source_url: str
    tlsh: str | None
    file_size: int | None
    distance: int
    size_ratio: float
    created_at: datetime


class DiffPairGroup(BaseModel):
    """Group of kits sharing an eTLD+1 domain that are diffable."""

    domain: str
    kits: list[DiffableKit]
    pair_count: int


class DiffPairGroupsResponse(BaseModel):
    groups: list[DiffPairGroup]
    total: int


class DiffCompareRequest(BaseModel):
    kit_a_id: uuid.UUID
    kit_b_id: uuid.UUID
    normalize: bool = False


class DiffKitContent(BaseModel):
    id: uuid.UUID
    source_url: str
    content: str
    file_size: int | None


class DiffChangeCategory(BaseModel):
    category: str
    count: int
    examples: list[str]


class DiffCompareSummary(BaseModel):
    structural_similarity: float
    tlsh_distance: int | None
    change_categories: list[DiffChangeCategory]


class DiffCompareResponse(BaseModel):
    kit_a: DiffKitContent
    kit_b: DiffKitContent
    summary: DiffCompareSummary
    normalized: bool
