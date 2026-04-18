"""Add auto_generated column to actors and backfill synthetic rows.

Part of the PhishMatch manual-first attribution redesign: the legacy
``correlate_kit_actors`` task minted synthetic actors named ``ACTOR-<hash>``
whenever any shared indicator crossed two kits, polluting analyst views.
Those auto-taps have been removed from the analysis chain; this migration:

1.  Adds an ``auto_generated`` boolean to mirror the column already present
    on ``campaigns`` (introduced in g7c3d4e5f6a8).
2.  Back-fills ``auto_generated = true`` for every actor whose name matches
    the ``ACTOR-XXXX`` synthetic pattern, so analyst UIs can hide them by
    default without dropping historical links.
3.  Indexes the column — the default list view filters on it.

Revision ID: q7m3n4o5p6h8
Revises: p6l2m3n4o5g7
Create Date: 2026-04-17 12:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

revision = "q7m3n4o5p6h8"
down_revision = "p6l2m3n4o5g7"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "actors",
        sa.Column(
            "auto_generated",
            sa.Boolean(),
            nullable=False,
            server_default="false",
        ),
    )
    op.create_index(
        "ix_actors_auto_generated", "actors", ["auto_generated"]
    )

    # Backfill synthetic actors minted by the now-retired correlate_kit_actors
    # task.  The task names them ``ACTOR-<8-char-hash>`` (see
    # darla.tasks.correlation._ensure_actor).  Anything matching that shape is
    # auto-generated; real analyst-created actors use descriptive names.
    op.execute(
        "UPDATE actors SET auto_generated = true "
        "WHERE name ~ '^ACTOR-[A-Fa-f0-9]{4,}$'"
    )

    # Defensive: ensure any campaigns minted by auto_assign_campaign that
    # somehow missed the flag (e.g. inserted before g7c3d4e5f6a8) are also
    # marked.  auto_assign_campaign names them ``AUTO-<actor>-<date>``.
    op.execute(
        "UPDATE campaigns SET auto_generated = true "
        "WHERE auto_generated = false AND name LIKE 'AUTO-%'"
    )


def downgrade() -> None:
    op.drop_index("ix_actors_auto_generated", table_name="actors")
    op.drop_column("actors", "auto_generated")
