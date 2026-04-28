"""Monitored-domain CRUD.

Operator-managed allowlist that gates Victim creation.  See
:mod:`darla.services.victim_service` for the matching extraction
logic and the rationale for the suffix-aware match.
"""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from darla.models.monitored_domain import MonitoredDomain


class MonitoredDomainService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def list_domains(
        self, offset: int = 0, limit: int = 200,
    ) -> tuple[list[MonitoredDomain], int]:
        query = select(MonitoredDomain).order_by(MonitoredDomain.domain)
        count_query = select(func.count(MonitoredDomain.id))
        total = (await self.db.execute(count_query)).scalar_one()
        result = await self.db.execute(query.offset(offset).limit(limit))
        return list(result.scalars().all()), total

    async def get_domain(
        self, domain_id: uuid.UUID,
    ) -> MonitoredDomain | None:
        result = await self.db.execute(
            select(MonitoredDomain).where(MonitoredDomain.id == domain_id)
        )
        return result.scalar_one_or_none()

    async def create_domain(self, data: dict) -> MonitoredDomain:
        # Lower-case at the boundary so observation queries can do a
        # plain ``==`` match without function-on-column overhead.
        domain = MonitoredDomain(
            domain=data["domain"].strip().lower(),
            description=data.get("description"),
        )
        self.db.add(domain)
        await self.db.flush()
        return domain

    async def update_domain(
        self, domain_id: uuid.UUID, data: dict,
    ) -> MonitoredDomain | None:
        domain = await self.get_domain(domain_id)
        if domain is None:
            return None
        if "domain" in data:
            domain.domain = data["domain"].strip().lower()
        if "description" in data:
            domain.description = data["description"]
        await self.db.flush()
        # Refresh so the post-flush ``updated_at`` (server-side
        # ``onupdate=now()``) is in-memory before pydantic serializes
        # it; otherwise the lazy-load fires under async and produces
        # a MissingGreenlet error.
        await self.db.refresh(domain)
        return domain

    async def delete_domain(self, domain_id: uuid.UUID) -> bool:
        """Removes the row from the allowlist.

        Existing :class:`Victim` rows are NOT cascaded — they survive
        for historical attack-surface visibility.  New observations
        of those emails won't create *new* Victim rows after the
        domain is removed, but the existing employees stay tracked.
        Re-add the domain to resume promotion of new observations.
        """
        domain = await self.get_domain(domain_id)
        if domain is None:
            return False
        await self.db.delete(domain)
        await self.db.flush()
        return True
