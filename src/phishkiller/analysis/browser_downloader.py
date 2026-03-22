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
            headless="virtual",
            humanize=True,
            block_webrtc=True,
            disable_coop=True,
            i_know_what_im_doing=True,
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

            # Give JS deobfuscation / eval layers time to execute
            # Many kits have multi-stage loaders that inject content via eval()
            await asyncio.sleep(random.uniform(3.0, 5.0))

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
    """Wait for Cloudflare Turnstile CAPTCHA and attempt to solve it.

    Turnstile renders a checkbox inside a cross-origin iframe from
    challenges.cloudflare.com.  Playwright's frame_locator fails on
    Firefox for cross-origin iframes (known bug #26317), so we iterate
    page.frames to find the challenge frame and click via bounding box.

    The checkbox sits on the left side of the Turnstile widget (~1/9th
    of the iframe width, vertically centered).
    """
    try:
        # Check if page has a Turnstile widget at all
        has_turnstile = await page.evaluate("""
            () => !!document.querySelector('.cf-turnstile, [data-sitekey]')
        """)
        if not has_turnstile:
            return

        logger.info("Turnstile widget found on page")

        # Give managed-mode a few seconds to auto-resolve
        await asyncio.sleep(random.uniform(2.5, 4.0))

        # Check if already solved (response token populated)
        if await _turnstile_solved(page):
            logger.info("Turnstile auto-resolved (managed mode)")
            await _wait_after_turnstile(page)
            return

        # Find the Turnstile iframe via page.frames (not frame_locator)
        frame_element = None
        for frame in page.frames:
            if "challenges.cloudflare.com" in frame.url:
                try:
                    frame_element = await frame.frame_element()
                    break
                except Exception:
                    continue

        if frame_element:
            box = await frame_element.bounding_box()
            if box:
                # Checkbox is on the left side of the widget
                click_x = box["x"] + box["width"] / 9
                click_y = box["y"] + box["height"] / 2
                logger.info(
                    "Clicking Turnstile iframe at (%.0f, %.0f)", click_x, click_y,
                )
                await page.mouse.click(click_x, click_y)
                await asyncio.sleep(random.uniform(1.5, 3.0))
        else:
            # Fallback: click the .cf-turnstile wrapper div
            widget = await page.query_selector(".cf-turnstile")
            if widget:
                box = await widget.bounding_box()
                if box:
                    click_x = box["x"] + 25
                    click_y = box["y"] + box["height"] / 2
                    logger.info(
                        "Clicking Turnstile wrapper at (%.0f, %.0f)",
                        click_x, click_y,
                    )
                    await page.mouse.click(click_x, click_y)
                    await asyncio.sleep(random.uniform(1.5, 3.0))
            else:
                logger.warning("Turnstile widget present but no clickable element found")
                return

        # Poll for the response token
        for attempt in range(12):
            if await _turnstile_solved(page):
                logger.info(
                    "Turnstile solved after click (attempt %d)", attempt + 1,
                )
                await _wait_after_turnstile(page)
                return
            await asyncio.sleep(1.0)

        logger.warning("Turnstile not solved after clicking — may need manual review")

    except Exception as e:
        logger.warning("Turnstile handling error: %s", e)


async def _turnstile_solved(page) -> bool:
    """Check if Turnstile response token has been populated."""
    return await page.evaluate("""
        () => {
            const resp = document.querySelector(
                'input[name="cf-turnstile-response"]'
            );
            return !!(resp && resp.value && resp.value.length > 0);
        }
    """)


async def _wait_after_turnstile(page) -> None:
    """Wait for post-Turnstile navigation or content swap."""
    await asyncio.sleep(random.uniform(2.0, 4.0))
    try:
        await page.wait_for_load_state("networkidle", timeout=10000)
    except Exception:
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
