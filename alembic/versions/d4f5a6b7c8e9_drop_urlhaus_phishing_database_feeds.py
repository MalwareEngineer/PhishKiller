"""Drop URLHAUS and PHISHING_DATABASE feed sources.

Both feeds are being removed from the pipeline:
- Phishing.Database: 0.07% download success rate, 765K dead URLs
- URLhaus: malware-focused, only 3.9% high-confidence phishing IOCs

Data purge is handled by scripts/drop_phishing_database_urlhaus.py
(must be run BEFORE this migration). This migration just retires the
enum values so they can't be reused.

Revision ID: d4f5a6b7c8e9
Revises: c3a7d5e9f1b2
Create Date: 2026-03-16 17:00:00.000000
"""
from alembic import op

revision = "d4f5a6b7c8e9"
down_revision = "c3a7d5e9f1b2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Rename enum values to mark as removed (PG doesn't support DROP VALUE)
    op.execute(
        "ALTER TYPE feedsource RENAME VALUE 'URLHAUS' TO '__REMOVED_URLHAUS'"
    )
    op.execute(
        "ALTER TYPE feedsource RENAME VALUE 'PHISHING_DATABASE' TO '__REMOVED_PHISHING_DATABASE'"
    )


def downgrade() -> None:
    op.execute(
        "ALTER TYPE feedsource RENAME VALUE '__REMOVED_URLHAUS' TO 'URLHAUS'"
    )
    op.execute(
        "ALTER TYPE feedsource RENAME VALUE '__REMOVED_PHISHING_DATABASE' TO 'PHISHING_DATABASE'"
    )
