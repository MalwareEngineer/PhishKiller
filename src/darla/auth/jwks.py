"""OIDC discovery + JWKS cache.

Validating an OIDC JWT signature requires the issuer's current public
keys.  The standard flow:

1. Fetch ``<issuer>/.well-known/openid-configuration`` once → take the
   ``jwks_uri`` field.
2. Fetch ``<jwks_uri>`` → an array of JWKs, each carrying a ``kid``
   (key ID).
3. The incoming JWT's header has a ``kid`` — pick the matching JWK and
   verify with it.

We cache both the discovery doc and the JWKS for ``oidc_jwks_cache_ttl``
seconds (default 1h).  A ``kid`` miss forces an immediate refresh
*regardless* of TTL — this is how legitimate IdP key rotations resolve
without operator intervention.

The cache is module-level state with an :class:`asyncio.Lock` to
prevent thundering-herd refresh under concurrent first-request load.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

import httpx

from darla.config import get_settings


class JWKSError(Exception):
    """Raised when the issuer's keys cannot be fetched or are malformed."""


@dataclass
class _JWKSCache:
    keys_by_kid: dict[str, dict[str, Any]] = field(default_factory=dict)
    fetched_at: float = 0.0  # monotonic timestamp
    jwks_uri: str = ""
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)


# Module-level singleton.  Reset by tests via :func:`_reset_cache_for_tests`.
_CACHE = _JWKSCache()


async def get_signing_key(kid: str) -> dict[str, Any]:
    """Return the JWK matching ``kid``.

    Refreshes the cache if (a) it's never been populated, (b) it's
    older than ``oidc_jwks_cache_ttl``, or (c) ``kid`` isn't in the
    current cache (legitimate-rotation fast path — refresh once, then
    look again before giving up).
    """
    settings = get_settings()
    now = time.monotonic()

    async with _CACHE.lock:
        cache_stale = (now - _CACHE.fetched_at) > settings.oidc_jwks_cache_ttl
        kid_missing = kid not in _CACHE.keys_by_kid
        if cache_stale or kid_missing or not _CACHE.keys_by_kid:
            await _refresh_locked()

        if kid not in _CACHE.keys_by_kid:
            # Even after a forced refresh the kid isn't there — token is
            # signed by a key the IdP doesn't acknowledge.  Could be a
            # forged token, an expired key the IdP no longer publishes,
            # or a misconfigured issuer.  Either way, reject.
            raise JWKSError(
                f"signing key {kid!r} not found in JWKS (refreshed); "
                "token may be forged or the IdP rotated keys aggressively"
            )
        return _CACHE.keys_by_kid[kid]


async def _refresh_locked() -> None:
    """Refetch the OIDC discovery doc and JWKS.  Caller must hold the lock."""
    settings = get_settings()
    async with httpx.AsyncClient(timeout=10.0) as client:
        # Step 1: resolve JWKS URI.  Skip discovery if the operator
        # pinned ``oidc_jwks_url`` explicitly.
        if settings.oidc_jwks_url:
            jwks_uri = settings.oidc_jwks_url
        else:
            if not settings.oidc_issuer:
                raise JWKSError(
                    "PK_OIDC_ISSUER is empty; cannot perform OIDC discovery"
                )
            disco_url = (
                settings.oidc_issuer.rstrip("/") + "/.well-known/openid-configuration"
            )
            try:
                disco_resp = await client.get(disco_url)
                disco_resp.raise_for_status()
            except httpx.HTTPError as e:
                raise JWKSError(f"OIDC discovery failed at {disco_url}: {e}") from e
            disco = disco_resp.json()
            jwks_uri = disco.get("jwks_uri", "")
            if not jwks_uri:
                raise JWKSError(
                    f"OIDC discovery doc at {disco_url} missing jwks_uri"
                )

        # Step 2: fetch JWKS.
        try:
            jwks_resp = await client.get(jwks_uri)
            jwks_resp.raise_for_status()
        except httpx.HTTPError as e:
            raise JWKSError(f"JWKS fetch failed at {jwks_uri}: {e}") from e
        jwks = jwks_resp.json()

    keys = jwks.get("keys", [])
    if not isinstance(keys, list) or not keys:
        raise JWKSError(f"JWKS at {jwks_uri} returned no keys")

    # Index by kid; ignore keys without a kid (we can't match them
    # against a JWT header anyway).
    new_keys = {k["kid"]: k for k in keys if isinstance(k, dict) and "kid" in k}
    if not new_keys:
        raise JWKSError(f"JWKS at {jwks_uri} has no usable kid-keyed keys")

    _CACHE.keys_by_kid = new_keys
    _CACHE.fetched_at = time.monotonic()
    _CACHE.jwks_uri = jwks_uri


def _reset_cache_for_tests() -> None:
    """Wipe the module-level cache.  Test-only — do not call from app code."""
    global _CACHE
    _CACHE = _JWKSCache()
