"""Monitored-domain allowlist driving Victim entity creation.

Operators maintain this list to gate which observed email addresses
are promoted to first-class :class:`Victim` rows.  The PhishPrint
sidebar is built around the assumption that "victims" means employees
of the organization being protected — emails on attacker-controlled
domains, drop addresses found in PHP configs, and other adversary-
side intel still get recorded as :class:`Indicator` rows (full
search/correlation), but never become Victim rows.

Without this allowlist, every random email an attacker happens to
encode into OAuth ``state`` would create a Victim.  That'd contaminate
the per-employee attack-surface view with addresses that aren't
employees at all.
"""

from __future__ import annotations

from sqlalchemy import String, Text
from sqlalchemy.orm import Mapped, mapped_column

from darla.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class MonitoredDomain(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "monitored_domains"

    # Stored lowercased.  Match logic is suffix-aware: a row of
    # ``acme.com`` matches both ``user@acme.com`` and
    # ``user@sub.acme.com``.  Subsidiaries that don't share the parent
    # domain (e.g. ``acme-hr.com``) need their own row.
    domain: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True,
    )
    description: Mapped[str | None] = mapped_column(Text)
