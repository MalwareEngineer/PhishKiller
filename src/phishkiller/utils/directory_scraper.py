"""Kit discovery utilities — URL path traversal and open directory scraping.

Inspired by kitphishr's approach: given a phishing URL, walk up the path tree
looking for downloadable kit archives and open directory listings.
"""

import logging
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

logger = logging.getLogger(__name__)

# Archive extensions we look for
ARCHIVE_EXTENSIONS = {".zip", ".tar.gz", ".tgz", ".gz", ".rar", ".7z", ".tar.bz2"}

# Content-Type values that indicate a downloadable archive
ARCHIVE_CONTENT_TYPES = {
    "application/zip",
    "application/x-zip-compressed",
    "application/x-rar-compressed",
    "application/gzip",
    "application/x-gzip",
    "application/x-tar",
    "application/x-7z-compressed",
    "application/octet-stream",
}

# Domains that are known false positives — never probe these
DOMAIN_BLOCKLIST = frozenset({
    "google.com", "www.google.com",
    "facebook.com", "www.facebook.com",
    "microsoft.com", "login.microsoftonline.com",
    "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com",
    "paypal.com", "www.paypal.com",
    "github.com", "raw.githubusercontent.com",
    "cloudflare.com",
    "twitter.com", "x.com",
    "linkedin.com",
    "instagram.com",
    "youtube.com",
    "netflix.com",
    "dropbox.com",
    "drive.google.com",
    "docs.google.com",
    "outlook.com", "outlook.live.com",
    "yahoo.com", "mail.yahoo.com",
})

# Minimum file size to consider (skip tiny files / error pages)
MIN_ARCHIVE_SIZE = 1024  # 1KB


def generate_probe_urls(url: str) -> list[dict]:
    """Generate directory + zip-guess URLs by walking up the path tree.

    Given: http://evil.com/foo/bar/login.php
    Produces:
        - http://evil.com/foo/bar/  (directory check)
        - http://evil.com/foo/bar.zip  (zip guess)
        - http://evil.com/foo/  (directory check)
        - http://evil.com/foo.zip  (zip guess)

    Stops before the domain root (too broad / noisy).

    Returns list of {"url": ..., "type": "directory"|"zip_guess"}
    """
    parsed = urlparse(url)

    if parsed.hostname and parsed.hostname.lower() in DOMAIN_BLOCKLIST:
        return []

    # Split path into segments, filter empty
    path = parsed.path.rstrip("/")
    segments = [s for s in path.split("/") if s]

    if not segments:
        return []

    base = f"{parsed.scheme}://{parsed.netloc}"
    probes = []

    # Walk from deepest directory up to one level above root
    # e.g. /foo/bar/login.php → check /foo/bar/, /foo/bar.zip, /foo/, /foo.zip
    for depth in range(len(segments), 0, -1):
        current_segments = segments[:depth]
        current_path = "/".join(current_segments)

        # Skip the root level (just the domain) — too noisy
        if depth <= 1 and len(segments) > 1:
            break

        # If the last segment has an extension, it's a file — go up one
        last = current_segments[-1]
        if "." in last and depth == len(segments):
            # This is the original file (e.g., login.php) — skip it,
            # but still check the parent directory
            dir_path = "/".join(current_segments[:-1])
            if dir_path:
                probes.append({
                    "url": f"{base}/{dir_path}/",
                    "type": "directory",
                })
                # Guess zip name from directory
                probes.append({
                    "url": f"{base}/{dir_path}.zip",
                    "type": "zip_guess",
                })
            continue

        # Directory listing check
        probes.append({
            "url": f"{base}/{current_path}/",
            "type": "directory",
        })

        # Zip guess — append .zip to the path segment
        probes.append({
            "url": f"{base}/{current_path}.zip",
            "type": "zip_guess",
        })

    return probes


class _OpenDirParser(HTMLParser):
    """Minimal HTML parser to extract href links from open directory pages."""

    def __init__(self):
        super().__init__()
        self.links: list[str] = []
        self.in_title = False
        self.title_text = ""

    def handle_starttag(self, tag, attrs):
        if tag == "title":
            self.in_title = True
        if tag == "a":
            for name, value in attrs:
                if name == "href" and value:
                    self.links.append(value)

    def handle_data(self, data):
        if self.in_title:
            self.title_text += data

    def handle_endtag(self, tag):
        if tag == "title":
            self.in_title = False


def parse_open_directory(html: str, base_url: str) -> list[str]:
    """Parse an 'Index of' page for archive file links.

    Returns list of absolute URLs to .zip/.tar.gz/.rar files.
    Returns empty list if the page doesn't look like a directory listing.
    """
    parser = _OpenDirParser()
    try:
        parser.feed(html)
    except Exception:
        return []

    # Check if this is actually an open directory listing
    if "index of" not in parser.title_text.lower():
        return []

    archive_urls = []
    for href in parser.links:
        href_lower = href.lower()

        # Check if the link points to an archive file
        is_archive = any(href_lower.endswith(ext) for ext in ARCHIVE_EXTENSIONS)
        if not is_archive:
            continue

        # Skip parent directory links
        if href in ("../", "..", "/"):
            continue

        # Resolve relative URLs
        absolute_url = urljoin(base_url, href)
        archive_urls.append(absolute_url)

    return archive_urls


def is_archive_response(response: httpx.Response, max_size_mb: int = 50) -> bool:
    """Check if an HTTP response looks like a downloadable archive.

    Uses Content-Type and Content-Length headers to decide without
    downloading the full file.
    """
    if response.status_code != 200:
        return False

    content_type = response.headers.get("content-type", "").lower().split(";")[0].strip()
    content_length = response.headers.get("content-length")

    # Must have an archive-like content type
    if content_type not in ARCHIVE_CONTENT_TYPES:
        return False

    # Check size bounds
    if content_length:
        size = int(content_length)
        if size < MIN_ARCHIVE_SIZE:
            return False
        if size > max_size_mb * 1024 * 1024:
            return False

    return True
