"""HTTP redirect chain tracker for investigation-mode downloads.

Manually follows redirects hop-by-hop to capture the full redirect chain,
instead of httpx's automatic follow_redirects=True which silently resolves.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path

import httpx

from phishkiller.config import get_settings
from phishkiller.utils.http_client import _extract_filename, _random_headers

logger = logging.getLogger(__name__)

MAX_REDIRECTS = 20


@dataclass
class RedirectHop:
    url: str
    status_code: int
    location: str | None = None
    server: str | None = None


@dataclass
class RedirectChain:
    hops: list[RedirectHop] = field(default_factory=list)
    final_url: str = ""
    total_redirects: int = 0

    def to_dict(self) -> dict:
        return {
            "hops": [
                {"url": h.url, "status_code": h.status_code,
                 "location": h.location, "server": h.server}
                for h in self.hops
            ],
            "final_url": self.final_url,
            "total_redirects": self.total_redirects,
        }

    @property
    def intermediate_urls(self) -> list[str]:
        """URLs from redirect hops (excluding initial and final)."""
        return [h.location for h in self.hops if h.location and h.location != self.final_url]


class RedirectTracker:
    """Download a URL while capturing the full redirect chain."""

    def download_with_redirects(
        self,
        url: str,
        dest_dir: str,
        max_size_mb: int = 50,
    ) -> tuple[Path | None, str, RedirectChain]:
        """Download a URL, capturing each redirect hop.

        Returns (filepath, reason, chain) — same interface as download_file()
        but with the redirect chain appended.
        """
        settings = get_settings()
        chain = RedirectChain()
        dest_path = Path(dest_dir)
        dest_path.mkdir(parents=True, exist_ok=True)
        max_bytes = max_size_mb * 1024 * 1024

        current_url = url
        redirect_codes = {301, 302, 303, 307, 308}

        try:
            # Use follow_redirects=False to capture each hop
            with httpx.Client(
                headers=_random_headers(),
                timeout=settings.download_timeout,
                follow_redirects=False,
            ) as client:
                # Follow redirects manually
                for _ in range(MAX_REDIRECTS):
                    response = client.get(current_url)

                    if response.status_code in redirect_codes:
                        location = response.headers.get("location", "")
                        chain.hops.append(RedirectHop(
                            url=current_url,
                            status_code=response.status_code,
                            location=location,
                            server=response.headers.get("server"),
                        ))
                        chain.total_redirects += 1

                        if not location:
                            chain.final_url = current_url
                            return None, "Redirect with no Location header", chain

                        # Handle relative redirects
                        if location.startswith("/"):
                            from urllib.parse import urlparse
                            parsed = urlparse(current_url)
                            location = f"{parsed.scheme}://{parsed.netloc}{location}"

                        current_url = location
                        continue

                    # Non-redirect response — this is the final destination
                    chain.final_url = current_url
                    response.raise_for_status()

                    # Stream the final response body to disk
                    filename = _extract_filename(current_url, response)
                    filepath = dest_path / filename

                    # For non-streaming response, write directly
                    content = response.content
                    if len(content) > max_bytes:
                        return None, f"Exceeded size limit ({max_size_mb} MB)", chain

                    filepath.write_bytes(content)
                    logger.info(
                        "Downloaded %s (%d bytes, %d redirects) to %s",
                        url, len(content), chain.total_redirects, filepath,
                    )
                    return filepath, "ok", chain

                # Exceeded max redirects
                chain.final_url = current_url
                return None, f"Exceeded max redirects ({MAX_REDIRECTS})", chain

        except httpx.HTTPStatusError as e:
            chain.final_url = current_url
            return None, f"HTTP {e.response.status_code}", chain
        except httpx.TimeoutException:
            chain.final_url = current_url
            return None, "Connection timed out", chain
        except httpx.RequestError as e:
            chain.final_url = current_url
            return None, f"Request error: {type(e).__name__}", chain
        except Exception as e:
            chain.final_url = current_url
            return None, f"Unexpected error: {type(e).__name__}", chain
