"""SVG static inspection — detects script-bearing SVGs and extracts referenced URLs.

Runs before the external-JS fetcher. When an EML carries an SVG attachment, we
need to know two things:

1. Does this SVG embed or reference executable script? (If no, it's a passive
   image and gets skipped by the script-fetching pipeline.)
2. What URLs does it statically reference? These feed the IOC extractor and
   get picked up by fetch_external_js for deeper follow-through.

No XML parsing — attackers commonly emit intentionally malformed XML to break
strict parsers. Regex scanning tolerates broken markup and misses fewer
obfuscation tricks.
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


# <script> / <svg:script> with any attributes (href, src, xlink:href)
_SCRIPT_OPEN_RE = re.compile(
    r"<\s*(?:[a-zA-Z][\w-]*:)?script\b",
    re.IGNORECASE,
)

# Pull href / src / xlink:href from any element that opens a <script> tag.
# Covers SVG 1.1 (xlink:href), SVG 2 (href), and stray HTML-style src=.
_SCRIPT_URL_RE = re.compile(
    r"""<\s*(?:[a-zA-Z][\w-]*:)?script\b[^>]*?
        (?:xlink:href|href|src)\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE | re.VERBOSE,
)

# Inline script body: <script>...</script>
_SCRIPT_BODY_RE = re.compile(
    r"<\s*(?:[a-zA-Z][\w-]*:)?script\b[^>]*>(.*?)<\s*/\s*(?:[a-zA-Z][\w-]*:)?script\s*>",
    re.IGNORECASE | re.DOTALL,
)

# URL-shaped strings inside inline script text (quoted http/https literals).
_INLINE_URL_RE = re.compile(
    r"""['"`](https?://[^\s'"`<>\]\\]{8,})['"`]""",
    re.IGNORECASE,
)

# Event-handler attributes: onload, onclick, onmouseover, etc.
_EVENT_HANDLER_RE = re.compile(
    r"""\bon[a-z]+\s*=\s*["']([^"']+)["']""",
    re.IGNORECASE,
)

# JavaScript: URL scheme inside an href/src attribute.
_JS_URL_SCHEME_RE = re.compile(
    r"""(?:href|src|xlink:href)\s*=\s*["']\s*javascript:""",
    re.IGNORECASE,
)

# <foreignObject> and <iframe> can host arbitrary HTML/script content.
_FOREIGN_CONTENT_RE = re.compile(
    r"<\s*(?:foreignObject|iframe)\b",
    re.IGNORECASE,
)

# <use> with an external href can pull in remote SVG content (SSRF on some renderers).
_USE_HREF_RE = re.compile(
    r"""<\s*use\b[^>]*?(?:xlink:href|href)\s*=\s*["'](https?://[^"']+)["']""",
    re.IGNORECASE,
)

# Indicators of obfuscation inside inline script bodies.
_OBFUSCATION_MARKERS = (
    ("fromcharcode", re.compile(r"\.fromCharCode\s*\(", re.IGNORECASE)),
    ("atob", re.compile(r"\batob\s*\(", re.IGNORECASE)),
    ("eval", re.compile(r"\beval\s*\(", re.IGNORECASE)),
    ("new_function", re.compile(r"\bnew\s+Function\s*\(", re.IGNORECASE)),
    ("unescape", re.compile(r"\bunescape\s*\(", re.IGNORECASE)),
    ("document_write", re.compile(r"\bdocument\.write\s*\(", re.IGNORECASE)),
)

# Max bytes to inspect — SVGs abusing size to DOS parsers get capped.
_MAX_INSPECT_BYTES = 5 * 1024 * 1024  # 5 MB


@dataclass
class SVGInspectionResult:
    """Structured output from SVG static inspection."""

    has_script: bool = False
    has_external_script: bool = False  # <script src=...>
    has_inline_script: bool = False    # <script>...</script> with body
    has_event_handlers: bool = False
    has_javascript_url: bool = False   # href="javascript:..."
    has_foreign_content: bool = False  # <foreignObject> / <iframe>
    has_obfuscation: bool = False
    obfuscation_markers: list[str] = field(default_factory=list)
    script_src_urls: list[str] = field(default_factory=list)
    inline_urls: list[str] = field(default_factory=list)
    use_href_urls: list[str] = field(default_factory=list)
    event_handler_snippets: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def all_urls(self) -> list[str]:
        """Deduplicated list of every URL statically referenced by the SVG."""
        seen: set[str] = set()
        out: list[str] = []
        for url in (*self.script_src_urls, *self.inline_urls, *self.use_href_urls):
            if url not in seen:
                seen.add(url)
                out.append(url)
        return out

    @property
    def is_suspicious(self) -> bool:
        """True if any script-bearing or dynamic construct is present."""
        return (
            self.has_script
            or self.has_event_handlers
            or self.has_javascript_url
            or self.has_foreign_content
        )


def inspect_bytes(raw: bytes) -> SVGInspectionResult:
    """Statically inspect SVG content without parsing XML."""
    result = SVGInspectionResult()

    if len(raw) > _MAX_INSPECT_BYTES:
        result.errors.append(f"truncated:{len(raw)}")
        raw = raw[:_MAX_INSPECT_BYTES]

    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception as e:
        result.errors.append(f"decode_error:{e}")
        return result

    # Script presence
    if _SCRIPT_OPEN_RE.search(text):
        result.has_script = True

    # <script src|href|xlink:href="..."> — external references
    for m in _SCRIPT_URL_RE.finditer(text):
        url = m.group(1).strip()
        if url:
            result.script_src_urls.append(url)
            result.has_external_script = True

    # Inline <script>...</script> bodies
    for m in _SCRIPT_BODY_RE.finditer(text):
        body = m.group(1) or ""
        if body.strip():
            result.has_inline_script = True
            for url_m in _INLINE_URL_RE.finditer(body):
                result.inline_urls.append(url_m.group(1).strip())
            for marker_name, marker_re in _OBFUSCATION_MARKERS:
                if marker_re.search(body):
                    result.has_obfuscation = True
                    if marker_name not in result.obfuscation_markers:
                        result.obfuscation_markers.append(marker_name)

    # Event-handler attributes on any element
    for m in _EVENT_HANDLER_RE.finditer(text):
        snippet = m.group(1).strip()
        if snippet:
            result.has_event_handlers = True
            # Cap each snippet length and overall count to keep payload small
            if len(result.event_handler_snippets) < 20:
                result.event_handler_snippets.append(snippet[:200])

    # javascript: URL scheme
    if _JS_URL_SCHEME_RE.search(text):
        result.has_javascript_url = True

    # <foreignObject> / <iframe> hosting arbitrary content
    if _FOREIGN_CONTENT_RE.search(text):
        result.has_foreign_content = True

    # <use href="https://..."> — remote SVG inclusion
    for m in _USE_HREF_RE.finditer(text):
        result.use_href_urls.append(m.group(1).strip())

    return result


def extract_inline_script_bodies(raw: bytes) -> list[str]:
    """Return the text of each inline ``<script>...</script>`` body in an SVG.

    Downstream deobfuscation uses this to run the JS deobfuscator over each
    script body independently, so an obfuscated URL-construction routine
    becomes plaintext JS a URL regex can hit.

    Bodies are returned verbatim (sans the enclosing tags); whitespace-only
    bodies are dropped.
    """
    if len(raw) > _MAX_INSPECT_BYTES:
        raw = raw[:_MAX_INSPECT_BYTES]
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        return []
    bodies: list[str] = []
    for m in _SCRIPT_BODY_RE.finditer(text):
        body = (m.group(1) or "").strip()
        if body:
            bodies.append(body)
    return bodies


def inspect_file(path: str | Path) -> SVGInspectionResult:
    """Read an SVG file from disk and inspect it."""
    fpath = Path(path)
    try:
        raw = fpath.read_bytes()
    except Exception as e:
        logger.debug("SVG read failed for %s: %s", path, e)
        return SVGInspectionResult(errors=[f"read_error:{e}"])
    return inspect_bytes(raw)
