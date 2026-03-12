"""HTTP client utilities for downloading kits and fetching feeds."""

import logging
from pathlib import Path

import httpx

from phishkiller.config import get_settings

logger = logging.getLogger(__name__)

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
}


def get_sync_client(**kwargs) -> httpx.Client:
    """Get a configured sync HTTP client for use in Celery tasks."""
    settings = get_settings()
    defaults = {
        "headers": DEFAULT_HEADERS,
        "timeout": settings.download_timeout,
        "follow_redirects": True,
    }
    defaults.update(kwargs)
    return httpx.Client(**defaults)


async def get_async_client(**kwargs) -> httpx.AsyncClient:
    """Get a configured async HTTP client."""
    settings = get_settings()
    defaults = {
        "headers": DEFAULT_HEADERS,
        "timeout": settings.download_timeout,
        "follow_redirects": True,
    }
    defaults.update(kwargs)
    return httpx.AsyncClient(**defaults)


def download_file(url: str, dest_dir: str, max_size_mb: int = 50) -> Path | None:
    """Download a file from URL to dest_dir. Returns the file path or None on failure.

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
                            return None
                        f.write(chunk)

                logger.info("Downloaded %s (%d bytes) to %s", url, total, filepath)
                return filepath

    except httpx.HTTPStatusError as e:
        logger.error("HTTP error downloading %s: %s", url, e.response.status_code)
    except httpx.RequestError as e:
        logger.error("Request error downloading %s: %s", url, e)
    except Exception as e:
        logger.error("Unexpected error downloading %s: %s", url, e)

    return None


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
