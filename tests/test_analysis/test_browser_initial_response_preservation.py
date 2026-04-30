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
