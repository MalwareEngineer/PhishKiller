"""Stealth browser downloader for Cloudflare-protected phishing pages.

Uses Camoufox (anti-detect Firefox) to bypass bot protection, Cloudflare
Turnstile CAPTCHAs, and anti-analysis JavaScript.  Falls back gracefully
when the ``camoufox`` package is not installed.

Requires the optional ``browser`` dependency group::

    pip install phishkiller[browser]
"""

import asyncio
import logging
import random
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# Cloudflare challenge indicators in response bodies / error reasons
_CF_CHALLENGE_MARKERS = (
    "challenges.cloudflare.com",
    "cf-turnstile",
    "cf_chl_opt",
    "jschl_vc",
    "Just a moment",
    "Checking your browser",
    "Attention Required",
)


def is_cloudflare_challenge(reason: str, response_body: str | None = None) -> bool:
    """Detect whether a download failure or response is a Cloudflare challenge.

    Returns True for ConnectError (TLS-level block), HTTP 403 with CF markers,
    or HTTP 200 pages containing Turnstile/challenge JavaScript.
    """
    if "ConnectError" in reason:
        return True
    if "HTTP 403" in reason:
        return True
    if response_body:
        for marker in _CF_CHALLENGE_MARKERS:
            if marker in response_body:
                return True
    return False


def _is_available() -> bool:
    """Check if Camoufox is installed."""
    try:
        import camoufox  # noqa: F401
        return True
    except ImportError:
        return False


async def _async_browser_download(
    url: str,
    dest_dir: str,
    timeout: int = 60,
) -> tuple[Path | None, str]:
    """Internal async implementation of the browser download."""
    try:
        from camoufox.async_api import AsyncCamoufox
    except ImportError:
        return None, "camoufox not installed (pip install phishkiller[browser])"

    dest_path = Path(dest_dir)
    dest_path.mkdir(parents=True, exist_ok=True)

    try:
        async with AsyncCamoufox(
            humanize=True,
            block_images=True,
            block_webrtc=True,
            geoip=True,
        ) as browser:
            page = await browser.new_page()

            # Set a realistic navigation timeout
            page.set_default_timeout(timeout * 1000)
            page.set_default_navigation_timeout(timeout * 1000)

            logger.info("Browser navigating to %s", url)
            response = await page.goto(url, wait_until="domcontentloaded")

            if not response:
                return None, "Browser navigation returned no response"

            # Wait for Turnstile widget to auto-resolve if present
            await _wait_for_turnstile(page)

            # Simulate minimal human behavior to pass behavioral checks
            await _simulate_human_behavior(page)

            # Wait for any post-challenge redirect or content load
            await page.wait_for_load_state("networkidle", timeout=15000)

            # Give anti-analysis JS time to run its scoring
            await asyncio.sleep(random.uniform(2.0, 4.0))

            # Capture final page content
            content = await page.content()
            final_url = page.url

            if not content or len(content) < 100:
                return None, "Browser captured empty or minimal page content"

            # Save HTML to disk
            filename = "page.html"
            filepath = dest_path / filename
            filepath.write_text(content, encoding="utf-8")

            logger.info(
                "Browser captured %d bytes from %s (final URL: %s)",
                len(content), url, final_url,
            )
            return filepath, "ok"

    except Exception as e:
        logger.error("Browser download failed for %s: %s", url, e)
        return None, f"Browser error: {type(e).__name__}: {e}"


async def _wait_for_turnstile(page) -> None:
    """Wait for Cloudflare Turnstile CAPTCHA to auto-resolve.

    Turnstile in 'managed' mode auto-passes for non-suspicious browsers.
    For 'interactive' mode, we try to click the checkbox.
    """
    try:
        turnstile_frame = page.frame_locator(
            "iframe[src*='challenges.cloudflare.com']"
        )
        # Check if Turnstile iframe exists (short timeout)
        checkbox = turnstile_frame.locator("input[type='checkbox']")
        if await checkbox.count() > 0:
            logger.info("Turnstile checkbox detected, clicking")
            await checkbox.click()
            # Wait for verification to complete
            await asyncio.sleep(random.uniform(3.0, 6.0))
        else:
            # Managed mode — may auto-resolve, give it time
            await asyncio.sleep(random.uniform(2.0, 4.0))
    except Exception:
        # No Turnstile present or it already resolved
        pass


async def _simulate_human_behavior(page) -> None:
    """Simulate minimal mouse movement and scrolling.

    Many phishing kits track mouse/keyboard events and score the interaction.
    Even basic movement with randomized timing can pass simple behavioral checks.
    """
    try:
        viewport = page.viewport_size or {"width": 1280, "height": 800}
        w, h = viewport["width"], viewport["height"]

        # Random mouse movements with natural-looking coordinates
        for _ in range(random.randint(3, 6)):
            x = random.randint(int(w * 0.1), int(w * 0.9))
            y = random.randint(int(h * 0.1), int(h * 0.7))
            await page.mouse.move(x, y)
            await asyncio.sleep(random.uniform(0.1, 0.4))

        # Small scroll
        await page.mouse.wheel(0, random.randint(50, 200))
        await asyncio.sleep(random.uniform(0.3, 0.8))

    except Exception:
        # Non-fatal — page may not support these interactions
        pass


def browser_download(
    url: str,
    dest_dir: str,
    timeout: int = 60,
) -> tuple[Path | None, str]:
    """Download a URL using a stealth browser (Camoufox).

    Synchronous wrapper around the async implementation for use in
    Celery tasks.  Returns ``(filepath, reason)`` matching the same
    interface as :func:`~phishkiller.utils.http_client.download_file`.
    """
    if not _is_available():
        return None, "camoufox not installed (pip install phishkiller[browser])"

    start = time.monotonic()
    try:
        loop = asyncio.new_event_loop()
        result = loop.run_until_complete(
            _async_browser_download(url, dest_dir, timeout)
        )
        elapsed = time.monotonic() - start
        logger.info("Browser download completed in %.1fs", elapsed)
        return result
    except Exception as e:
        elapsed = time.monotonic() - start
        logger.error("Browser download wrapper failed after %.1fs: %s", elapsed, e)
        return None, f"Browser error: {type(e).__name__}: {e}"
    finally:
        loop.close()
