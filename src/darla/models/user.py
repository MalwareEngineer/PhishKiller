"""User model — local mirror of OIDC-authenticated identities.

Darla does not own identities; the configured OIDC provider does (Entra in
the reference deployment, but any compliant provider works — see
``docs/auth/oidc-generic.md`` once Phase 8 ships).  This table exists only
to:

* Give us a stable internal UUID to reference from audit and attribution
  rows when a user might be renamed in the IdP (``upn`` changes, ``oid``
  does not).
* Cache the user's display fields so the UI doesn't have to call back
  into the IdP for every list render.
* Provide a **local kill switch** (``disabled_at``) and a CLI-set
  **role override** that wins over whatever the IdP claim says — both
  needed because IdP group changes can take up to ~1hr to propagate via
  token refresh, and ops needs an instant lever.

Rows are created **just-in-time** the first time the auth middleware
sees a valid token for a given subject.  There is no admin "create user"
flow — onboarding is handled entirely by the IdP (add the user to the
right group, they log in, the row appears).

See ``RFC 0001`` in the deployment repo for the full design rationale.
"""

from __future__ import annotations

import enum
from datetime import datetime

from sqlalchemy import DateTime, Enum, String
from sqlalchemy.orm import Mapped, mapped_column

from darla.models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class UserRole(enum.StrEnum):
    """Coarse-grained authorization role.

    Two values is intentional — three would imply a permissions model
    (RBAC engine, permissions table, role-permission joins) we explicitly
    don't want.  Anything more nuanced belongs in the CLI admin tooling
    (``darla-admin``), not the HTTP authorization layer.

    * ``VIEWER`` — read-only across the full platform (kits, IOCs, actors,
      campaigns, investigations, victims).  Cannot submit, reanalyze, or
      annotate.
    * ``ANALYST`` — viewer + write access (submit kits, trigger
      reanalysis, attribute kits to actors/campaigns, edit notes).
    """

    VIEWER = "viewer"
    ANALYST = "analyst"


class User(UUIDPrimaryKeyMixin, TimestampMixin, Base):
    __tablename__ = "users"

    # OIDC ``sub`` claim by default; configurable per IdP via
    # ``PK_OIDC_SUBJECT_CLAIM`` (Entra deployments override to ``oid``
    # because Entra's ``sub`` is per-app pairwise and would change if we
    # ever spin up a second app registration).  128 chars covers every
    # spec-compliant subject value we've seen — Entra ``oid`` is a UUID,
    # Okta uses 20-char IDs, Auth0 uses ``provider|id`` strings up to
    # ~80 chars.
    oidc_subject: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True, index=True,
    )

    # Snapshots from the most recent token, refreshed on every login.
    # We store these for UI display and audit-log readability — never
    # trust them for authorization (always re-derive role from the live
    # token claims).  ``upn`` is typically email-shaped but the spec
    # doesn't guarantee that, so we treat it as opaque text.
    upn: Mapped[str] = mapped_column(String(255), nullable=False)
    display_name: Mapped[str] = mapped_column(String(255), nullable=False)

    # Role derived from the IdP role claim on the most recent login.
    # The middleware always re-reads this from the token and writes it
    # here on every request, so out-of-band group changes propagate
    # within one token refresh (typically <=1hr for Entra).
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), nullable=False)

    # CLI emergency lever — when set, wins over ``role`` regardless of
    # what the token claim says.  Use case: an analyst is being
    # offboarded and IT hasn't propagated the group removal yet, so ops
    # SSMs into the API container and runs ``darla-admin user
    # set-role-override <subject> viewer`` to immediately downgrade.
    # Cleared with ``darla-admin user clear-role-override``.
    role_override: Mapped[UserRole | None] = mapped_column(
        Enum(UserRole), nullable=True,
    )

    # Refreshed on every authenticated request.  Useful for "who's been
    # active this week" admin queries and for spotting stale accounts
    # the IdP forgot to deprovision.
    last_login_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
    )

    # Local kill switch.  Middleware rejects any request from a user
    # with ``disabled_at IS NOT NULL`` regardless of token validity.
    # Set via ``darla-admin user disable <subject>``; cleared with
    # ``darla-admin user enable <subject>``.  Distinct from IdP-side
    # disablement because token refresh lag means IdP changes don't
    # take effect for up to ~1hr.
    disabled_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )

    @property
    def effective_role(self) -> UserRole:
        """Role actually used for authorization decisions.

        Resolves ``role_override`` if set, otherwise falls back to the
        IdP-derived ``role``.  Always call this — never read ``role``
        directly in authorization paths or you'll bypass the override.
        """
        return self.role_override if self.role_override is not None else self.role

    def __repr__(self) -> str:
        return (
            f"<User(id={self.id}, upn={self.upn!r}, "
            f"role={self.effective_role.value}"
            f"{', disabled' if self.disabled_at else ''})>"
        )
