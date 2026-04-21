"""browser_svg_runner unit tests — helpers only.

The live Camoufox path is covered by integration runs inside
worker-browser; here we exercise the pure-Python helpers (dawa derivation,
landing classifier, wrapper HTML, filename sanitiser) and the camoufox-
missing fallback path. The live detonation happens against a controlled
synthetic SVG in the integration suite.
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from darla.analysis import browser_svg_runner as bsr
from darla.analysis.browser_svg_runner import (
    SVGExecResult,
    _build_wrapper_html,
    _looks_like_landing,
    _sanitize_filename,
    _should_capture_body,
    derive_dawa_from_email,
    execute_svg_with_capture,
)


# ---------------------------------------------------------------------------
# derive_dawa_from_email
# ---------------------------------------------------------------------------

def test_derive_dawa_matches_b64_of_email() -> None:
    email = "victim@example.com"
    out = derive_dawa_from_email(email)
    assert out is not None
    # Real loader templates decode back via atob().
    assert base64.b64decode(out).decode() == email


def test_derive_dawa_strips_whitespace() -> None:
    assert derive_dawa_from_email("  v@x.com\n") == derive_dawa_from_email("v@x.com")


@pytest.mark.parametrize("empty", [None, "", "   "])
def test_derive_dawa_handles_empty(empty) -> None:
    # Whitespace-only should decode to empty bytes; None/"" returns None.
    out = derive_dawa_from_email(empty)
    if empty is None or empty == "":
        assert out is None
    else:
        # Whitespace gets stripped → empty input → still produces "" b64
        assert out == ""


# ---------------------------------------------------------------------------
# _looks_like_landing
# ---------------------------------------------------------------------------

def test_landing_classifier_accepts_html_document() -> None:
    assert _looks_like_landing("text/html; charset=utf-8", 200, "document")


def test_landing_classifier_accepts_fetch_xhtml() -> None:
    assert _looks_like_landing("application/xhtml+xml", 200, "fetch")


def test_landing_classifier_rejects_javascript() -> None:
    assert not _looks_like_landing(
        "application/javascript", 200, "script",
    )


def test_landing_classifier_rejects_image_resource() -> None:
    assert not _looks_like_landing("text/html", 200, "image")


def test_landing_classifier_rejects_bad_status() -> None:
    assert not _looks_like_landing("text/html", 404, "document")
    assert not _looks_like_landing("text/html", 500, "document")


# ---------------------------------------------------------------------------
# _should_capture_body
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ct,expected", [
    ("text/html", True),
    ("text/html; charset=utf-8", True),
    ("application/javascript", True),
    ("application/json", True),
    ("application/xhtml+xml", True),
    ("image/png", False),
    ("font/woff2", False),
    ("video/mp4", False),
    ("application/octet-stream", False),
])
def test_body_capture_filter(ct: str, expected: bool) -> None:
    assert _should_capture_body(ct) is expected


# ---------------------------------------------------------------------------
# _build_wrapper_html
# ---------------------------------------------------------------------------

def test_wrapper_embeds_svg_body() -> None:
    svg = "<svg xmlns='http://www.w3.org/2000/svg'><rect/></svg>"
    html = _build_wrapper_html(svg, dawa_value=None)
    assert svg in html
    # No dawa init when None.
    assert "window.dawa" not in html


def test_wrapper_injects_dawa_before_svg() -> None:
    svg = "<svg><script>/*payload*/</script></svg>"
    dawa = "dGVzdEB4LmNvbQ=="  # base64("test@x.com")
    html = _build_wrapper_html(svg, dawa_value=dawa)
    # Must land BEFORE the SVG body so inline scripts see it.
    dawa_pos = html.find("window.dawa")
    svg_pos = html.find("<svg")
    assert 0 <= dawa_pos < svg_pos
    # Value is JSON-encoded to defuse injection.
    assert json.dumps(dawa) in html


def test_wrapper_escapes_dawa_to_defuse_script_break() -> None:
    # If dawa_value contained a quote, a naive f-string would produce
    # broken JS.  json.dumps wraps it in quotes and escapes internals
    # so the injected value stays a single string literal.
    hostile = 'a";alert(1);//'
    html = _build_wrapper_html("<svg/>", dawa_value=hostile)
    # The JSON-encoded form must appear verbatim, which requires the
    # hostile quote to be escaped.
    assert json.dumps(hostile) in html
    # The raw unescaped quote-break must NOT appear — that would detach
    # alert(1) from the string literal and make it live JS.
    assert 'a";alert(1);//' not in html


# ---------------------------------------------------------------------------
# _sanitize_filename
# ---------------------------------------------------------------------------

def test_sanitize_filename_uses_path_leaf() -> None:
    name = _sanitize_filename("https://x.test/path/to/file.js?foo=bar", 5)
    assert name.startswith("005_")
    assert name.endswith("file.js")


def test_sanitize_filename_falls_back_to_hostname() -> None:
    name = _sanitize_filename("https://x.test/", 7)
    assert name == "007_x.test"


def test_sanitize_filename_caps_length() -> None:
    long_leaf = "a" * 500 + ".js"
    name = _sanitize_filename(f"https://x.test/{long_leaf}", 1)
    # Leaf body is capped at 80 chars after the "NNN_" prefix.
    assert len(name) <= 4 + 80 + 4  # prefix + leaf + extension slack


# ---------------------------------------------------------------------------
# execute_svg_with_capture fallback when Camoufox is unavailable
# ---------------------------------------------------------------------------

def test_camoufox_missing_returns_graceful_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If camoufox import fails, harness must surface a structured status,
    not raise.  Callers tolerate this so Docker images without the browser
    extra don't crash the analysis chain."""
    svg = tmp_path / "stub.svg"
    svg.write_text(
        "<svg xmlns='http://www.w3.org/2000/svg' width='10' height='10'/>",
        encoding="utf-8",
    )

    # Force the ImportError path regardless of whether camoufox is
    # installed in the test environment.
    import sys
    import types

    fake = types.ModuleType("camoufox")
    fake.async_api = None  # importing async_api will AttributeError, but
    # the code uses ``from camoufox.async_api import AsyncCamoufox`` which
    # raises ImportError when the submodule is missing. Simulate by setting
    # sys.modules with a broken submodule.
    monkeypatch.setitem(sys.modules, "camoufox", fake)
    monkeypatch.setitem(sys.modules, "camoufox.async_api", types.ModuleType("camoufox.async_api"))

    # Now the import succeeds but the attribute lookup fails — wrap that as
    # a missing-camoufox by deleting AsyncCamoufox from the fake module.
    # The harness treats ImportError specifically; AttributeError would
    # bubble up. So instead, use the "camoufox missing" path by having
    # from-import raise ImportError via the __getattr__ hook.
    def _raise_import_error(name: str):
        raise ImportError(f"no attr {name}")
    sys.modules["camoufox.async_api"].__getattr__ = _raise_import_error  # type: ignore[attr-defined]

    out_dir = tmp_path / "out"
    result = execute_svg_with_capture(
        svg, out_dir, dawa_value=None, timeout=5, max_requests=10,
    )
    assert isinstance(result, SVGExecResult)
    assert result.status == "camoufox_missing"
    assert result.urls_discovered == []
    assert result.terminal_urls == []


def test_svg_read_error_returns_error_status(tmp_path: Path) -> None:
    # Point at a nonexistent file; Camoufox may or may not be present but
    # the read happens first.  Either way we get a structured error.
    missing = tmp_path / "does_not_exist.svg"
    out_dir = tmp_path / "out"
    result = execute_svg_with_capture(
        missing, out_dir, dawa_value=None, timeout=5, max_requests=10,
    )
    # Either camoufox_missing (Camoufox absent → exits before read) or
    # error (Camoufox present → reads, fails).  Both must be non-OK.
    assert result.status in {"camoufox_missing", "error"}
    assert result.urls_discovered == []
