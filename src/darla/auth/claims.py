"""Configurable JWT-claim path resolution.

Different OIDC providers stash roles under different claim names — and
some put them inside nested objects.  Examples we have to handle:

  * Entra:    ``roles`` (top-level array of strings)
  * Okta:     ``groups`` (top-level array of strings)
  * Auth0:    ``https://your-app.example.com/roles`` (top-level, custom
              namespace, the URL is literally the claim key)
  * Keycloak: ``realm_access.roles`` (nested — ``realm_access`` is an
              object, ``roles`` is a key inside it)

Rather than ship per-IdP code, we treat the role claim as a configurable
**dotted path** (``PK_OIDC_ROLE_CLAIM``).  The resolver walks the path
through nested dicts and returns the leaf as a list of strings.

Same machinery handles the subject claim (``PK_OIDC_SUBJECT_CLAIM``),
though in practice subjects are always top-level.
"""

from __future__ import annotations

from typing import Any


def resolve_claim_path(claims: dict[str, Any], path: str) -> Any:
    """Look up ``path`` inside ``claims``.

    ``path`` is a dotted string.  An empty segment is illegal; a missing
    segment returns ``None``.  Crucially, **dotted lookup falls back to
    a literal key match at the top level** — Auth0's role claim is
    literally the URL ``https://your-app.example.com/roles``, complete
    with dots, and treating that as a path would mean walking through
    nonexistent ``https:`` and ``//your-app`` keys.

    Examples::

        resolve_claim_path({"roles": ["a"]}, "roles")
        # → ["a"]

        resolve_claim_path({"realm_access": {"roles": ["a"]}}, "realm_access.roles")
        # → ["a"]

        resolve_claim_path({"https://x/roles": ["a"]}, "https://x/roles")
        # → ["a"]   (literal-key fallback, even though the path "looks" dotted)

        resolve_claim_path({"a": {"b": 1}}, "a.missing")
        # → None
    """
    if not path:
        raise ValueError("claim path must be non-empty")

    # Literal-key fallback first — covers Auth0's URL-namespaced claims
    # without forcing operators to escape dots.  If a top-level key
    # exactly matches the path, return it.  Only descends into the
    # dotted-walk path if there's no literal match.
    if path in claims:
        return claims[path]

    parts = path.split(".")
    if any(p == "" for p in parts):
        raise ValueError(f"claim path {path!r} contains empty segments")

    cur: Any = claims
    for part in parts:
        if not isinstance(cur, dict):
            return None
        if part not in cur:
            return None
        cur = cur[part]
    return cur


def claim_to_role_strings(value: Any) -> list[str]:
    """Coerce a claim leaf into a list of role-name strings.

    The role claim's wire shape varies — most providers ship an array
    of strings, but some emit a single string when there's only one
    role assigned, and Keycloak-style RPT shows up as
    ``{"roles": [...]}`` even at the leaf.  This normalises the
    common cases so the middleware sees a uniform ``list[str]``.

    Anything else (numbers, None, weird nested shapes) becomes an
    empty list — the middleware treats "no roles" the same as "no
    role assigned" and rejects with 403.
    """
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str)]
    if isinstance(value, dict) and "roles" in value:
        return claim_to_role_strings(value["roles"])
    return []
