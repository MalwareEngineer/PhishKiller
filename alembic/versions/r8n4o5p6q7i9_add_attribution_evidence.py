"""Add attribution evidence columns to kit_actors / kit_families / campaign_kits.

Supports PhishMatch's manual-first attribution model: every link records who
decided, when, at what confidence, and a JSONB snapshot of the scoring
signals that supported the decision at the moment it was made.

Revision ID: r8n4o5p6q7i9
Revises: q7m3n4o5p6h8
Create Date: 2026-04-17 12:30:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB


revision = "r8n4o5p6q7i9"
down_revision = "q7m3n4o5p6h8"
branch_labels = None
depends_on = None


_TABLES = ("kit_actors", "family_kits", "campaign_kits")


def upgrade() -> None:
    for table in _TABLES:
        op.add_column(
            table,
            sa.Column("attributed_by", sa.String(255), nullable=True),
        )
        op.add_column(
            table,
            sa.Column(
                "attributed_at",
                sa.DateTime(timezone=True),
                nullable=True,
                server_default=sa.text("now()"),
            ),
        )
        op.add_column(
            table,
            sa.Column("confidence", sa.String(32), nullable=True),
        )
        op.add_column(
            table,
            sa.Column("evidence_snapshot", JSONB, nullable=True),
        )

    # Backfill: every pre-existing link is a legacy auto-correlation — mark
    # it as such so the UI can visually distinguish it from PhishMatch and
    # analyst links.  ``NULL`` attributed_by + ``legacy_auto`` confidence
    # lets us filter these out of "verified" views while preserving history.
    for table in _TABLES:
        op.execute(
            f"UPDATE {table} "
            f"SET confidence = 'legacy_auto' "
            f"WHERE confidence IS NULL"
        )


def downgrade() -> None:
    for table in _TABLES:
        op.drop_column(table, "evidence_snapshot")
        op.drop_column(table, "confidence")
        op.drop_column(table, "attributed_at")
        op.drop_column(table, "attributed_by")
