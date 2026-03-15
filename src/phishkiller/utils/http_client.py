"""HTTP client utilities for downloading kits and fetching feeds."""

import json
import logging
import random
from pathlib import Path

import httpx
import redis

from phishkiller.config import get_settings

logger = logging.getLogger(__name__)

# Top 20 browser User-Agent strings for rotation — mix of Chrome, Firefox,
# Edge, and Safari across Windows, macOS, and Linux to avoid fingerprinting.
USER_AGENTS = [
    # Chrome (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    # Chrome (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Chrome (Linux)
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    # Firefox (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    # Firefox (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Firefox (Linux)
    "Mozilla/5.0 (X11; Linux x86_64; rv:133.0) Gecko/20100101 Firefox/133.0",
    # Edge (Windows)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
    # Safari (macOS)
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Safari/605.1.15",
    # Safari (iPhone)
    "Mozilla/5.0 (iPhone; CPU iPhone OS 18_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Mobile/15E148 Safari/604.1",
    # Chrome (Android)
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36",
]


def _random_headers() -> dict[str, str]:
    """Return headers with a randomly selected User-Agent."""
    return {"User-Agent": random.choice(USER_AGENTS)}


def get_sync_client(**kwargs) -> httpx.Client:
    """Get a configured sync HTTP client for use in Celery tasks."""
    settings = get_settings()
    defaults = {
        "headers": _random_headers(),
        "timeout": settings.download_timeout,
        "follow_redirects": True,
    }
    defaults.update(kwargs)
    return httpx.Client(**defaults)


def fetch_with_cache(
    url: str, *, timeout: int = 120, headers: dict | None = None,
) -> httpx.Response | None:
    """Fetch a URL with ETag/If-Modified-Since caching via Redis.

    Returns the response on 200, or None on 304 Not Modified (caller should
    skip ingestion). Falls back to unconditional GET if Redis is unavailable.
    """
    settings = get_settings()
    cache_key = f"feed_cache:{url}"
    conditional_headers: dict[str, str] = {}

    # Try to load cached ETag/Last-Modified from Redis
    try:
        r = redis.from_url(settings.redis_url)
        cached = r.get(cache_key)
        if cached:
            meta = json.loads(cached)
            if meta.get("etag"):
                conditional_headers["If-None-Match"] = meta["etag"]
            if meta.get("last_modified"):
                conditional_headers["If-Modified-Since"] = meta["last_modified"]
    except Exception:
        logger.debug("Redis unavailable for feed cache, using unconditional GET")

    # Merge conditional headers with any caller-supplied headers
    merged_headers = {**(headers or {}), **conditional_headers}

    with get_sync_client(timeout=timeout) as client:
        response = client.get(url, headers=merged_headers)

    if response.status_code == 304:
        logger.info("Feed %s: 304 Not Modified, skipping ingestion", url[:80])
        return None

    response.raise_for_status()

    # Cache the response's ETag/Last-Modified for next time
    try:
        meta = {
            "etag": response.headers.get("etag"),
            "last_modified": response.headers.get("last-modified"),
        }
        r = redis.from_url(settings.redis_url)
        r.setex(cache_key, 86400, json.dumps(meta))
    except Exception:
        logger.debug("Failed to cache feed headers in Redis for %s", url[:80])

    return response


async def get_async_client(**kwargs) -> httpx.AsyncClient:
    """Get a configured async HTTP client."""
    settings = get_settings()
    defaults = {
        "headers": _random_headers(),
        "timeout": settings.download_timeout,
        "follow_redirects": True,
    }
    defaults.update(kwargs)
    return httpx.AsyncClient(**defaults)


def download_file(
    url: str, dest_dir: str, max_size_mb: int = 50,
) -> tuple[Path | None, str]:
    """Download a file from URL to dest_dir.

    Returns (filepath, reason) — filepath is None on failure,
    reason is "ok" on success or a short error description.
    Streams the download to enforce size limits without loading into memory.
    """
    dest_path = Path(dest_dir)
    dest_path.mkdir(parents=True, exist_ok=True)
    max_bytes = max_size_mb * 1024 * 1024

    try:
        with get_sync_client() as client:
            with client.stream("GET", url) as response:
                response.raise_for_status()

                # Determine filename from URL or Content-Disposition
                filename = _extract_filename(url, response)
                filepath = dest_path / filename

                total = 0
                with open(filepath, "wb") as f:
                    for chunk in response.iter_bytes(chunk_size=8192):
                        total += len(chunk)
                        if total > max_bytes:
                            logger.warning(
                                "Download exceeded size limit (%d MB): %s",
                                max_size_mb,
                                url,
                            )
                            filepath.unlink(missing_ok=True)
                            return None, f"Exceeded size limit ({max_size_mb} MB)"

                        f.write(chunk)

                logger.info("Downloaded %s (%d bytes) to %s", url, total, filepath)
                return filepath, "ok"

    except httpx.HTTPStatusError as e:
        logger.error("HTTP error downloading %s: %s", url, e.response.status_code)
        return None, f"HTTP {e.response.status_code}"
    except httpx.TimeoutException as e:
        logger.error("Timeout downloading %s: %s", url, e)
        return None, "Connection timed out"
    except httpx.RequestError as e:
        logger.error("Request error downloading %s: %s", url, e)
        return None, f"Request error: {type(e).__name__}"
    except Exception as e:
        logger.error("Unexpected error downloading %s: %s", url, e)
        return None, f"Unexpected error: {type(e).__name__}"


def _extract_filename(url: str, response: httpx.Response) -> str:
    """Extract a safe filename from URL or Content-Disposition header."""
    # Try Content-Disposition
    cd = response.headers.get("content-disposition", "")
    if "filename=" in cd:
        parts = cd.split("filename=")
        if len(parts) > 1:
            name = parts[1].strip('" ')
            if name:
                return _sanitize_filename(name)

    # Fall back to URL path
    from urllib.parse import urlparse

    path = urlparse(url).path
    name = path.split("/")[-1] if "/" in path else "download"
    return _sanitize_filename(name) if name else "download.bin"


def _sanitize_filename(name: str) -> str:
    """Remove dangerous characters from a filename."""
    keep = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-")
    return "".join(c if c in keep else "_" for c in name)[:255] or "download.bin"
