"""add unique constraint on analysis_results(kit_id, analysis_type)

Revision ID: l2h8i9j0k1c3
Revises: k1g7h8i9j0b2
Create Date: 2026-03-31

"""
from typing import Sequence, Union

from alembic import op

revision: str = "l2h8i9j0k1c3"
down_revision: Union[str, None] = "k1g7h8i9j0b2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Remove existing duplicates first, keeping the newest per (kit_id, analysis_type)
    op.execute("""
        DELETE FROM analysis_results
        WHERE id NOT IN (
            SELECT DISTINCT ON (kit_id, analysis_type) id
            FROM analysis_results
            ORDER BY kit_id, analysis_type, created_at DESC
        )
    """)
    op.create_unique_constraint(
        "uq_kit_analysis_type", "analysis_results", ["kit_id", "analysis_type"]
    )


def downgrade() -> None:
    op.drop_constraint("uq_kit_analysis_type", "analysis_results", type_="unique")
