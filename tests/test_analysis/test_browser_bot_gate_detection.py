"""Structural regression guards for browser_downloader bot-gate detection.

The full ``_detect_bot_gate`` logic runs as JS inside a live Playwright
page — covered by integration detonation, not by unit tests.  This file
guards the specific selectors and strategies that address gaps seen in
real kits, so a refactor can't silently drop them:

  * **Fake click-captcha gate** (kit ``eae2ac74-be7a-4db1-90cf-db9df0be5056``)
    — ``#captcha-box``/``.captcha-wrapper`` wrapping an AITM cred harvester
    with ``wss://user.cheacker.store/*`` exfil.  The previous detection
    missed it because body innerText had no gate vocabulary and there was
    no form.  Strategy 0 now scans for ``captcha``/``human-check``/
    ``human-verif`` class/id tokens as a high-confidence structural hint.
"""

from __future__ import annotations

import inspect

from darla.analysis import browser_downloader


def _source_of(obj) -> str:
    return inspect.getsource(obj)


# ---------------------------------------------------------------------------
# Strategy 0 — captcha class/id detection
# ---------------------------------------------------------------------------

def test_detect_bot_gate_scans_captcha_class_tokens() -> None:
    """Legitimate login pages don't use ``captcha`` in element class names;
    fake click-captcha templates almost always do.  The querySelector
    must cover class AND id substrings for both ``captcha`` and the
    ``human-*`` variants seen in the wild."""
    src = _source_of(browser_downloader._detect_bot_gate)
    # Substring selectors — keep these exact so attacker-template
    # variations ("captcha-wrapper", "clickcaptcha", "human-check-v2")
    # all match.
    required_selectors = [
        '[class*="captcha"]',
        '[id*="captcha"]',
        '[class*="human-check"]',
        '[class*="human-verif"]',
    ]
    for sel in required_selectors:
        assert sel in src, f"detect_bot_gate lost selector: {sel!r}"


def test_detect_bot_gate_emits_fake_captcha_gate_type() -> None:
    """Strategy 0 must surface a dedicated ``fake_captcha_gate`` type —
    the bypass flow treats it like an auto-submit-form gate (waits for
    navigation after click) rather than a simple button."""
    src = _source_of(browser_downloader._detect_bot_gate)
    assert "'fake_captcha_gate'" in src or '"fake_captcha_gate"' in src


def test_bypass_waits_for_navigation_on_fake_captcha_gate() -> None:
    """After clicking a fake_captcha_gate, the bypass must call the
    form-submit wait (polls for URL change / networkidle) rather than
    the simple gate-resolution wait — these gates typically navigate
    or swap the DOM into a cred harvester."""
    src = _source_of(browser_downloader._attempt_bot_gate_bypass)
    # The conditional must include fake_captcha_gate in the set of
    # types that trigger _wait_for_form_submit.
    assert "fake_captcha_gate" in src, (
        "bypass flow must route fake_captcha_gate through "
        "_wait_for_form_submit"
    )


# ---------------------------------------------------------------------------
# WebSocket capture wiring — regression guard on the handler registration.
# ---------------------------------------------------------------------------

def test_websocket_handler_registered_on_page() -> None:
    """``page.on('websocket', _on_websocket)`` MUST be registered in
    both navigation contexts (initial goto + turnstile-retry fresh
    page), or AITM cred-relay frames are silently dropped."""
    src = _source_of(browser_downloader._async_browser_download)
    # Both registrations — the fresh-context retry re-creates the page
    # and must re-attach handlers.
    assert src.count('page.on("websocket"') >= 2, (
        "page.on('websocket', ...) must be attached on BOTH the initial "
        "page and the turnstile-retry fresh page"
    )


def test_websocket_frames_persisted_when_captured() -> None:
    """Captured frames must be persisted to ``websocket_frames.jsonl``
    — this is how the AITM wss:// protocol ends up reviewable after
    the kit finishes."""
    src = _source_of(browser_downloader._async_browser_download)
    assert "websocket_frames.jsonl" in src
