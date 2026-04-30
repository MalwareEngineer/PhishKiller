"""Structural guard on the cross-origin redirect preservation logic in
``browser_download``.

The full async function spins up Camoufox + Playwright and drives a
real browser, so a hermetic functional test is impractical here.
Instead we lock in the *decision logic* via source inspection — the
specific failure mode this guards against is: kit lands on a decoy
domain after a cloak-and-redirect gate (temu.com / dhgate / mvideo)
and the original gate HTML — which is the only content with
attribution value — gets dropped on the floor by the de-duplication
branch that skips ``resp["url"] == url``.

If anyone unintentionally restores the old skip-the-original behavior
this test will catch it before the next investigation comes back
'stuck on temu.com.'
"""

from __future__ import annotations

import inspect

from darla.analysis import browser_downloader


def _src() -> str:
    """Return the source of the async browser_download orchestrator."""
    return inspect.getsource(browser_downloader._async_browser_download)


def test_redirect_preserves_initial_html() -> None:
    """When ``final_url != url`` and the captured response list
    contains an HTML body for the original URL, that body must be
    saved as ``initial.html`` so IOC / YARA / TLSH and the inspector
    view all see the gate."""
    src = _src()
    assert "initial.html" in src, (
        "browser_download dropped initial.html preservation — the gate "
        "HTML on cross-origin redirects will be lost again"
    )
    # The gate is preserved iff a redirect actually happened.
    assert "final_url != url" in src
    # We only promote text/html responses (don't store binary bodies).
    assert "html" in src and "content_type" in src


def test_initial_html_added_to_manifest() -> None:
    """The manifest entry must include both the URL we asked for
    (``url``, the gate) and a ``role`` field so downstream tools
    can distinguish 'what we asked for' from 'where we ended up.'"""
    src = _src()
    assert '"role": "initial"' in src
    assert '"role": "final"' in src
    assert '"filename": "initial.html"' in src


def test_initial_html_not_duplicated_under_browser_resources() -> None:
    """If we promoted the initial response to ``initial.html``, the
    same body must not also be saved under ``_browser_resources/`` —
    otherwise the same HTML appears twice and the IOC scanner
    double-counts indicators."""
    src = _src()
    assert "saved_initial_html and resp[\"url\"] == url" in src


# ---------------------------------------------------------------------------
# Fix B — IP/geo cloak interception across multiple lookup services
# ---------------------------------------------------------------------------

def test_cloak_interception_covers_observed_endpoints() -> None:
    """The cloak-interception list must include the IP-lookup services
    we've actually observed in failed kits.  ``ipapi.is`` is the one
    that bounced investigation 7bbf2c92 to temu.com — without it
    intercepted, the gate's JS sees our worker's datacenter ASN and
    redirects to a benign decoy site."""
    from darla.analysis import browser_downloader

    patterns = browser_downloader._CLOAK_ROUTE_PATTERNS
    # The endpoint that actually bounced us.
    assert any("ipapi.is" in p for p in patterns)
    # Plus the original ipinfo.io we already supported.
    assert any("ipinfo.io" in p for p in patterns)
    # And other common ones we know phishing kits hit.
    expected_substrings = (
        "ipapi.co", "ipify.org", "ip-api.com", "geoplugin.net",
    )
    missing = [
        s for s in expected_substrings
        if not any(s in p for p in patterns)
    ]
    assert not missing, (
        f"Cloak-route list missing common services: {missing}"
    )


def test_spoofed_response_signals_residential_clean_ip() -> None:
    """The spoofed cloak response must signal a clean residential IP
    across the field-name variants the different services emit.
    ``ipapi.is`` checks ``is_hosting`` / ``is_datacenter`` — those must
    be False or the gate redirects.  ``ipinfo.io`` reads ``org`` —
    must look like an ISP, not a cloud provider."""
    from darla.analysis import browser_downloader

    spoof = browser_downloader._SPOOFED_RESIDENTIAL_IP
    # ipapi.is fields — these are the ones that matter for the
    # observed bounce-to-temu pattern.
    assert spoof.get("is_hosting") is False
    assert spoof.get("is_datacenter") is False
    assert spoof.get("is_proxy") is False
    assert spoof.get("is_vpn") is False
    # ipinfo.io / generic
    assert "Comcast" in spoof.get("org", "")
    assert spoof.get("country") == "US"


def test_cloak_routes_registered_via_helper() -> None:
    """``_register_cloak_routes`` must be called once per page.  This
    test pins both that the helper exists and that it's invoked from
    the main download orchestrator (so a future fresh-context retry
    inherits the interception)."""
    from darla.analysis import browser_downloader

    assert hasattr(browser_downloader, "_register_cloak_routes")
    src = inspect.getsource(browser_downloader._async_browser_download)
    assert "_register_cloak_routes" in src


# ---------------------------------------------------------------------------
# Fix A — gate detector priority (form-driven > verify-button)
# ---------------------------------------------------------------------------

def test_detector_skips_verify_button_when_form_driven() -> None:
    """When a page has a hidden submit-token form AND a small
    clickable element AND gate text, the detector must skip
    Strategy 1 (verify_button) so Strategy 2 / 4 can return the
    checkbox / form-submit element instead.

    This is the c0bbdf54 'stuck at gate' failure: detector matched
    a "Verify" anchor via Strategy 1, clicked it, the gate JS
    cleared its wrapper but never POSTed the form because the form
    was wired to the *checkbox*, not the link."""
    src = inspect.getsource(browser_downloader._detect_bot_gate)
    # The skip predicate must check all three signals together.
    assert "skipVerifyButtonStrategy" in src
    assert "submitTokenForm" in src
    assert "smallClickable" in src
    # Must guard the Strategy 1 loop — verify_button must NOT be
    # returned when the skip flag is set.
    assert "if (!skipVerifyButtonStrategy)" in src


def test_detector_submit_token_form_selector_matches_observed_gates() -> None:
    """The hidden-form selector must catch the field naming the
    'Security Verification' kit actually uses
    (``click_captcha_token``, ``_click_captcha``, ``_force_captcha``,
    ``_captcha_redirect``).  The selector targets ``name*="token"`` and
    ``name*="captcha"`` substrings; both must be present."""
    src = inspect.getsource(browser_downloader._detect_bot_gate)
    assert 'name*="token"' in src
    assert 'name*="captcha"' in src
