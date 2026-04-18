"""Many-to-many association tables.

The kit ↔ actor / family / campaign junctions carry *attribution evidence*
columns so every link tells the analyst who decided, when, at what
confidence, and which signals supported the decision:

- ``attributed_by``     — analyst username, or ``None`` for
                          legacy auto-links.  Set to ``"system:phishmatch"``
                          by scoring-engine shortcuts when used.
- ``attributed_at``     — timestamp the link was created.  Defaults to
                          ``now()`` at the DB level.
- ``confidence``        — ``verified`` (analyst is certain) or
                          ``suspected`` (provisional / PhishMatch suggestion
                          promoted without deep review).  Stored as a plain
                          ``String`` so new values can be added without an
                          enum migration.
- ``evidence_snapshot`` — JSONB blob capturing the PhishMatch signals that
                          supported the link at the moment of attribution
                          (TLSH nearest-neighbour, IOC overlap counts, YARA
                          rule overlap, etc.).  This is *intentionally*
                          denormalised — the signals shift as new kits come
                          in and we want an immutable audit trail.

The ``campaign_actors`` / ``family_actors`` tables are left as plain
junctions for now; they are analyst-curated scaffolding (campaign "has"
these actors), not per-kit evidence.
"""

from sqlalchemy import Column, DateTime, ForeignKey, String, Table, text
from sqlalchemy.dialects.postgresql import JSONB, UUID

from darla.models.base import Base

_EVIDENCE_COLUMNS = lambda: [  # noqa: E731 — lambda keeps columns hashable per-table
    Column("attributed_by", String(255), nullable=True),
    Column(
        "attributed_at",
        DateTime(timezone=True),
        nullable=True,
        server_default=text("now()"),
    ),
    Column("confidence", String(32), nullable=True),
    Column("evidence_snapshot", JSONB, nullable=True),
]


campaign_kits = Table(
    "campaign_kits",
    Base.metadata,
    Column(
        "campaign_id",
        UUID(as_uuid=True),
        ForeignKey("campaigns.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "kit_id",
        UUID(as_uuid=True),
        ForeignKey("kits.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    *_EVIDENCE_COLUMNS(),
)

campaign_actors = Table(
    "campaign_actors",
    Base.metadata,
    Column(
        "campaign_id",
        UUID(as_uuid=True),
        ForeignKey("campaigns.id"),
        primary_key=True,
    ),
    Column(
        "actor_id",
        UUID(as_uuid=True),
        ForeignKey("actors.id"),
        primary_key=True,
    ),
)

family_kits = Table(
    "family_kits",
    Base.metadata,
    Column(
        "family_id",
        UUID(as_uuid=True),
        ForeignKey("families.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "kit_id",
        UUID(as_uuid=True),
        ForeignKey("kits.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    *_EVIDENCE_COLUMNS(),
)

family_actors = Table(
    "family_actors",
    Base.metadata,
    Column(
        "family_id",
        UUID(as_uuid=True),
        ForeignKey("families.id"),
        primary_key=True,
    ),
    Column(
        "actor_id",
        UUID(as_uuid=True),
        ForeignKey("actors.id"),
        primary_key=True,
    ),
)

kit_actors = Table(
    "kit_actors",
    Base.metadata,
    Column(
        "kit_id",
        UUID(as_uuid=True),
        ForeignKey("kits.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "actor_id",
        UUID(as_uuid=True),
        ForeignKey("actors.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    *_EVIDENCE_COLUMNS(),
)


# Confidence enum values as module constants.  Not a Postgres enum so the
# set can expand without a migration.
CONFIDENCE_VERIFIED = "verified"
CONFIDENCE_SUSPECTED = "suspected"
CONFIDENCE_VALUES = {CONFIDENCE_VERIFIED, CONFIDENCE_SUSPECTED}
