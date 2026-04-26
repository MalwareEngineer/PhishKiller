"""drop UNIQUE on kits.sha256, replace with regular index

Cross-investigation kits that land on the same attacker AITM/relay
infrastructure legitimately share a SHA256.  The UNIQUE constraint
forced us to either fail the second kit on commit or null its hashes
to dodge the violation — both options lost analysis data on the
correlated investigation.  Drop the UNIQUE; keep a non-unique index
for SHA256 lookup performance.  ``duplicate_of_kit_id`` carries the
correlation pointer.

Revision ID: w3s9t0u1v2n4
Revises: v2r8s9t0u1m3
Create Date: 2026-04-25

"""
from typing import Sequence, Union

from alembic import op

revision: str = "w3s9t0u1v2n4"
down_revision: Union[str, None] = "v2r8s9t0u1m3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # In Postgres, ``unique=True`` on a column produces a UNIQUE INDEX
    # (not a separate UNIQUE constraint).  Drop and recreate.  The
    # initial-schema migration named it ``ix_kits_sha256``.
    op.drop_index("ix_kits_sha256", table_name="kits")
    op.create_index("ix_kits_sha256", "kits", ["sha256"], unique=False)


def downgrade() -> None:
    # Recreating the UNIQUE index will FAIL if any duplicate sha256
    # values exist (from cross-investigation kits accumulated after
    # this migration shipped).  Operators downgrading must first
    # resolve duplicates manually — there's no safe automatic path.
    op.drop_index("ix_kits_sha256", table_name="kits")
    op.create_index("ix_kits_sha256", "kits", ["sha256"], unique=True)
