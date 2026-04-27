"""Victim model — first-class entity for monitored-domain employees.

The PhishPrint side of the platform inverts the data model: instead
of looking at threats and asking "who'd they hit?", we look at people
and ask "what's been thrown at them?"  Every email observed across
the analysis pipeline whose domain matches a row in
:class:`MonitoredDomain` becomes a Victim, with a junction row
(:class:`KitVictim`) recording each per-kit observation and its
source channel (OAuth state, login_hint, EML To-header, AITM URL
fragment, etc.).

Non-monitored emails (attacker drops, kit-credential mailers, test
addresses) are NOT promoted to Victims — they stay as
:class:`Indicator` rows with appropriate ``context`` so the per-kit
indicators panel still surfaces them as IOCs.

Operators can edit ``display_name``, ``type``, and ``notes`` from
the victim detail page.  Auto-classification at observation time
flags obvious service accounts (``noreply@``, ``postmaster@``) so
operators don't have to triage them.  Everything else defaults to
``user`` and stays operator-editable.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Enum, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from darla.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin

if TYPE_CHECKING:
    from darla.models.kit import Kit


class VictimType(enum.StrEnum):
    """Operator-facing classification of a Victim row."""

    USER = "user"                      # individual employee (default)
    EXEC = "exec"                      # high-value target (VP, C-suite)
    DISTRO = "distro"                  # mailing list (team-foo@)
    SHARED_MAILBOX = "shared_mailbox"  # functional inbox (support@, billing@)
    SERVICE = "service"                # automated sender (noreply@, postmaster@)
    UNKNOWN = "unknown"                # classification pending review


class VictimObservationSource(enum.StrEnum):
    """Where a kit_victims observation was extracted from."""

    OAUTH_STATE = "oauth_state"             # b64-decoded ``state`` param
    OAUTH_LOGIN_HINT = "oauth_login_hint"   # ``login_hint`` query param
    AITM_URL_FRAGMENT = "aitm_url_fragment"  # ``redirect_uri#email`` smuggling
    EML_TO = "eml_to"                       # ``To:`` header in an .eml lure
    EML_CC = "eml_cc"
    EML_BCC = "eml_bcc"
    KIT_CONTENT = "kit_content"             # email found inside kit content
    OTHER = "other"


class Victim(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "victims"

    email: Mapped[str] = mapped_column(
        String(320), nullable=False, unique=True, index=True,
    )
    # Denormalized + indexed for fast "show me all victims at @acme.com"
    # filtering on the PhishPrint list page.  Always the lower-cased
    # part after the @ in ``email``.
    domain: Mapped[str] = mapped_column(String(255), nullable=False, index=True)

    # Operator-editable.  Populating this turns the canonical email
    # key into a human-readable "Firstname Lastname — Role" label in
    # the PhishPrint UI without losing the keyed lookup.
    display_name: Mapped[str | None] = mapped_column(String(255))
    type: Mapped[VictimType] = mapped_column(
        Enum(VictimType), nullable=False, default=VictimType.USER,
        server_default=VictimType.USER.value,
    )
    notes: Mapped[str | None] = mapped_column(Text)

    # First/last seen are auto-maintained by ``VictimService.observe``
    # — derived from the earliest/latest ``observed_at`` across the
    # kit_victims junction.  We denormalize to skip an aggregate query
    # on every list-page render.
    first_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    observations: Mapped[list[KitVictim]] = relationship(
        back_populates="victim", cascade="all, delete-orphan",
    )


class KitVictim(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    """Junction row recording one observation of a Victim within a Kit.

    A single victim can be observed multiple times in the same kit
    (e.g. once via ``oauth_state`` and again via the ``aitm_url_fragment``
    when the browser-rendered final URL carries the same email).  Each
    observation gets its own row so the per-victim detail page can
    show the source-channel breakdown.
    """

    __tablename__ = "kit_victims"

    kit_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("kits.id", ondelete="CASCADE"),
        nullable=False,
    )
    victim_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("victims.id", ondelete="CASCADE"),
        nullable=False,
    )
    source: Mapped[VictimObservationSource] = mapped_column(
        Enum(VictimObservationSource), nullable=False,
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )

    victim: Mapped[Victim] = relationship(back_populates="observations")
    kit: Mapped[Kit] = relationship()

    __table_args__ = (
        Index("ix_kit_victims_kit_id", "kit_id"),
        Index("ix_kit_victims_victim_id", "victim_id"),
        # Compound index drives the "for this kit, what victims did we
        # observe via what channels" query on the kit detail page.
        Index("ix_kit_victims_kit_source", "kit_id", "source"),
    )
