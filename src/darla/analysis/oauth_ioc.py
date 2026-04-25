"""OAuth authorize URL IOC extractor.

Consent-phishing / illicit-consent-grant campaigns use OAuth ``authorize``
URLs (most commonly Microsoft Identity Platform v2.0) as the **lure itself**
— the victim clicks a URL pointing at ``login.microsoftonline.com`` or
``login.live.com`` with a ``client_id`` the attacker registered as a
third-party app.  The attacker's registered ``redirect_uri`` then either
silently receives a real authorization code (if silent auth succeeds) or
bounces the victim to an AITM credential harvester with the victim's email
smuggled through the ``state`` parameter.

Key observation: **all of this is recoverable from the URL itself**,
independent of whether we successfully download the kit.  Microsoft can
(and does) disable malicious apps; attacker infra can (and does) go down.
But the URL — captured from the phishing email or SMS — preserves the
campaign fingerprint:

  * ``client_id``         — the Azure app registration (stable campaign IOC)
  * ``tenant``            — ``common`` / ``consumers`` / specific tenant GUID
  * ``scope``             — what the attacker intended to exfil (Graph read,
                            Mail.Read, offline_access, etc.)
  * ``state``             — often contains victim context (email) base64-
                            encoded; reveals the attacker knew the victim
                            before the click
  * ``redirect_uri``      — the attacker's callback, when specified in URL
                            rather than relying on app registration default
  * ``login_hint``        — victim email pre-fill, direct PII leak

This module is intentionally side-effect-free so it can run early in
``download_kit``, *before* any network activity, and still emit IOCs even
when the fetch path fails downstream.
"""

from __future__ import annotations

import base64
import re
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# Host / path matchers
# ---------------------------------------------------------------------------

# Microsoft Identity Platform v2 (work/school + personal) and consumer MSA.
# Also covers v1 (``/oauth2/authorize``) and the legacy MSA handoff endpoint.
_OAUTH_HOST_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    # login.microsoftonline.com/{tenant}/oauth2/{v2.0/}?authorize
    re.compile(
        r"^login(?:-us)?\.microsoftonline\.(?:com|us)$"
    ),
    # login.live.com/oauth20_authorize.srf (consumer MSA handoff target)
    re.compile(r"^login\.live\.com$"),
    # login.microsoftonline-p.com — partner auth fronting
    re.compile(r"^login\.microsoftonline-p\.com$"),
)

_OAUTH_PATH_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"^/[^/]+/oauth2/(?:v2\.0/)?authorize/?$"),
    re.compile(r"^/oauth20_authorize\.srf/?$"),
)

# When ``state`` looks like base64 and decodes to printable ASCII/UTF-8 with
# an email-shaped substring, we surface the decoded form alongside the raw
# value.  We don't overwrite the raw state — operators need both.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_B64_RE = re.compile(r"^[A-Za-z0-9+/=_\-]+$")


def is_oauth_authorize_url(url: str | None) -> bool:
    """Return True if ``url`` is an OAuth authorize endpoint worth
    extracting IOCs from.

    Matches Microsoft Identity Platform v1/v2 and consumer MSA.  Does NOT
    match the consent page proper (``/adminconsent``) or token exchange
    (``/oauth2/*/token``) — only the user-facing authorize entry point
    that shows up in phishing lures.
    """
    if not url or not isinstance(url, str):
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    if not any(p.match(host) for p in _OAUTH_HOST_PATH_PATTERNS):
        return False
    path = parsed.path or "/"
    return any(p.match(path) for p in _OAUTH_PATH_PATTERNS)


def _try_decode_b64_state(raw: str) -> str | None:
    """If ``raw`` looks like base64 and decodes to a printable string,
    return the decoded form; else return None.

    The real-world pattern: attackers base64-encode the victim's email
    into ``state`` so their AITM backend can correlate the click with
    the outbound lure (e.g. ``aG9uZGF5QGJ2LmNvbQ==`` → ``honday@bv.com``).
    We deliberately return None on non-decodable garbage rather than
    guessing — a raw state value like ``csrf-abc123`` must not be
    presented as if it were decoded PII.
    """
    if not raw or not _B64_RE.match(raw):
        return None
    # Urlsafe variants are common; try both.
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            # Pad to multiple of 4 — attackers often strip trailing '='.
            padded = raw + "=" * (-len(raw) % 4)
            decoded = decoder(padded, validate=False)
        except Exception:
            continue
        try:
            text = decoded.decode("utf-8")
        except UnicodeDecodeError:
            continue
        # Require the decoded form to be mostly printable; reject
        # binary-looking output that just happened to survive base64.
        printable = sum(1 for c in text if c.isprintable() or c in "\n\r\t")
        if printable < len(text) * 0.9:
            continue
        return text
    return None


def _extract_tenant(path: str) -> str | None:
    """Return the ``{tenant}`` segment from ``/{tenant}/oauth2/...``.

    Typical values: ``common``, ``consumers``, ``organizations``, or a
    specific tenant GUID.  Consumer MSA (``login.live.com``) has no
    tenant segment, so this returns None for that path shape.
    """
    m = re.match(r"^/([^/]+)/oauth2/(?:v2\.0/)?authorize/?$", path)
    return m.group(1) if m else None


def extract_oauth_iocs(url: str | None) -> dict | None:
    """Extract IOCs from a Microsoft OAuth authorize URL.

    Returns ``None`` if ``url`` is not an OAuth authorize URL we understand.
    The returned dict is stable and JSON-serializable — it's stored as the
    ``result_data`` of an ``AnalysisType.OAUTH_AUTHORIZE`` analysis result.

    The returned schema is intentionally flat so operators can search on
    it (e.g. ``result_data->>'client_id'`` in SQL).  Fields not present in
    the URL are omitted — don't emit nulls that look like signal.
    """
    if not is_oauth_authorize_url(url):
        return None

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    # Use keep_blank_values=True so single-use flags (e.g. ``prompt=``)
    # are still visible as indicators.
    qs = parse_qs(parsed.query, keep_blank_values=True)

    def first(key: str) -> str | None:
        values = qs.get(key)
        return values[0] if values else None

    result: dict = {
        "provider": "microsoft",
        "host": host,
        "path": path,
    }
    tenant = _extract_tenant(path)
    if tenant:
        result["tenant"] = tenant

    client_id = first("client_id")
    if client_id:
        result["client_id"] = client_id

    # Normalize scope — Microsoft accepts both ``+``- and space-separated
    # scope lists.  We split so the reviewer can see the intent at a
    # glance (``Mail.Read`` vs ``offline_access`` vs ``User.Read``).
    scope_raw = first("scope")
    if scope_raw:
        result["scope_raw"] = scope_raw
        result["scopes"] = [s for s in re.split(r"[\s+]+", scope_raw) if s]

    for key in (
        "response_type",
        "response_mode",
        "redirect_uri",
        "prompt",
        "login_hint",
        "nonce",
        "code_challenge",
        "code_challenge_method",
        "domain_hint",
    ):
        value = first(key)
        if value:
            result[key] = value

    # State is always preserved raw; we also try to decode it if it looks
    # like base64.  Surface any email we find as a top-level
    # ``victim_email`` field — that's the IOC that binds the lure to a
    # specific recipient.
    state = first("state")
    if state:
        result["state_raw"] = state
        decoded = _try_decode_b64_state(state)
        if decoded is not None:
            result["state_decoded"] = decoded
            email_match = _EMAIL_RE.search(decoded)
            if email_match:
                result["victim_email"] = email_match.group(0)

    # Heuristic: ``prompt=none`` with no session → Microsoft returns an
    # OAuth error *to the redirect_uri*.  Attackers use this so that
    # even logged-out victims bounce to the AITM proxy.
    if first("prompt") == "none":
        result["silent_auth_abuse"] = True

    return result
