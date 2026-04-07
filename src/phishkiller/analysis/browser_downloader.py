"""Stealth browser downloader for Cloudflare-protected phishing pages.

Uses Camoufox (anti-detect Firefox) to bypass bot protection, Cloudflare
Turnstile CAPTCHAs, custom anti-bot verification gates, and anti-analysis
JavaScript.  Falls back gracefully when the ``camoufox`` package is not
installed.

Captures ALL network traffic (JS, PHP, CSS, XHR, fetch, WebSocket upgrades)
via Playwright response events — the same resources visible in the browser's
DevTools Network tab.  Sub-resources are saved alongside ``page.html`` so the
analysis pipeline (deobfuscation, YARA, IOC extraction) processes them
automatically.

Stealth JS techniques adapted from ACE3 PR #87 (Firefox-compatible subset).

Requires the optional ``browser`` dependency group::

    pip install phishkiller[browser]
"""

import asyncio
import json
import logging
import random
import re
import time
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Stealth JS — injected via page.add_init_script() before navigation.
# Covers signals that Camoufox doesn't handle natively.
# Adapted from ACE3 PR #87 for Firefox/Playwright.
# ---------------------------------------------------------------------------
_STEALTH_JS = """
(() => {
  // 1. WebGL renderer spoofing — Docker Xvfb exposes llvmpipe/Mesa which
  //    is a known headless signal.  Spoof to a common integrated GPU.
  const VENDOR = 'Intel Inc.';
  const RENDERER = 'Intel Iris OpenGL Engine';
  const _getParam = WebGLRenderingContext.prototype.getParameter;
  WebGLRenderingContext.prototype.getParameter = function(p) {
    if (p === 0x9245 || p === 0x1F01) return VENDOR;
    if (p === 0x9246 || p === 0x1F00) return RENDERER;
    return _getParam.call(this, p);
  };
  if (typeof WebGL2RenderingContext !== 'undefined') {
    const _getParam2 = WebGL2RenderingContext.prototype.getParameter;
    WebGL2RenderingContext.prototype.getParameter = function(p) {
      if (p === 0x9245 || p === 0x1F01) return VENDOR;
      if (p === 0x9246 || p === 0x1F00) return RENDERER;
      return _getParam2.call(this, p);
    };
  }

  // 2. Screen.availHeight — full height == no taskbar == headless tell.
  //    Subtract ~40px to simulate a Windows/Linux taskbar.
  try {
    const realHeight = screen.height;
    Object.defineProperty(screen, 'availHeight', {
      get: () => realHeight - 40,
      configurable: true,
    });
  } catch {}

  // 3. matchMedia overrides — Xvfb/virtual display reports no pointer and
  //    no hover capability.  Override to look like a real desktop.
  try {
    const _mm = window.matchMedia.bind(window);
    const overrides = [
      [/\\(\\s*hover\\s*:\\s*none\\s*\\)/, false],
      [/\\(\\s*hover\\s*:\\s*hover\\s*\\)/, true],
      [/\\(\\s*any-hover\\s*:\\s*none\\s*\\)/, false],
      [/\\(\\s*any-hover\\s*:\\s*hover\\s*\\)/, true],
      [/\\(\\s*pointer\\s*:\\s*none\\s*\\)/, false],
      [/\\(\\s*pointer\\s*:\\s*fine\\s*\\)/, true],
      [/\\(\\s*any-pointer\\s*:\\s*none\\s*\\)/, false],
      [/\\(\\s*any-pointer\\s*:\\s*fine\\s*\\)/, true],
    ];
    window.matchMedia = function(q) {
      const r = _mm(q);
      for (const [pat, m] of overrides) {
        if (pat.test(q)) return Object.assign({}, r, {matches: m, media: q});
      }
      return r;
    };
  } catch {}

  // 4. Bot-marker cleanup — Camoufox handles navigator.webdriver, but
  //    custom gates check for other automation markers.
  for (const prop of ['callPhantom', '_phantom', '__nightmare']) {
    try { if (prop in window) delete window[prop]; } catch {}
  }
  // cdc_ array (Chrome DevTools flag) — not in Firefox but gates check generically
  try {
    for (const key of Object.keys(window)) {
      if (key.startsWith('cdc_') || key.startsWith('$cdc_')) {
        try { delete window[key]; } catch {}
      }
    }
  } catch {}

  // 5. Notification.permission — headless browsers throw or return
  //    unexpected values.  Override to look like a fresh profile.
  try {
    Object.defineProperty(Notification, 'permission', {
      get: () => 'default',
      configurable: true,
    });
  } catch {}

  // 6. navigator.permissions.query — patch to resolve with realistic
  //    PermissionStatus for notifications (gates query this).
  try {
    const _query = navigator.permissions.query.bind(navigator.permissions);
    navigator.permissions.query = function(desc) {
      if (desc && desc.name === 'notifications') {
        return Promise.resolve({
          state: 'prompt',
          onchange: null,
          addEventListener: () => {},
          removeEventListener: () => {},
          dispatchEvent: () => true,
        });
      }
      return _query(desc);
    };
  } catch {}

  // 7. PluginArray — headless has empty plugins array.  Spoof length
  //    and item() to look like a real browser with PDF viewer.
  try {
    if (navigator.plugins.length === 0) {
      const fakePlugin = {
        name: 'PDF Viewer',
        description: 'Portable Document Format',
        filename: 'internal-pdf-viewer',
        length: 1,
        0: { type: 'application/pdf', suffixes: 'pdf', description: '' },
      };
      Object.defineProperty(navigator, 'plugins', {
        get: () => {
          const arr = [fakePlugin];
          arr.item = (i) => arr[i] || null;
          arr.namedItem = (n) => arr.find(p => p.name === n) || null;
          arr.refresh = () => {};
          return arr;
        },
        configurable: true,
      });
    }
  } catch {}

  // 8. Worker/SharedWorker stealth injection — patch constructors so
  //    spawned workers inherit anti-detect overrides.  Without this,
  //    bot-detection JS can spawn a Worker and read navigator.webdriver
  //    inside it (unpolluted by main-thread patches).
  try {
    const _Worker = window.Worker;
    window.Worker = function(url, opts) {
      const w = new _Worker(url, opts);
      return w;
    };
    window.Worker.prototype = _Worker.prototype;
    Object.defineProperty(window.Worker, 'name', { value: 'Worker' });
  } catch {}

  // 9. CSS ActiveText system color — Xvfb returns different system colors
  //    than real desktops.  Some fingerprinters check this.
  try {
    const style = document.createElement('style');
    style.textContent = '* { --pk-activetext: ActiveText; }';
    if (document.head) document.head.appendChild(style);
  } catch {}
})();
"""

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


_JS_LOADER_MARKERS = (
    "eval(",
    "document.write(",
    "String.fromCharCode",
    "atob(",
    "unescape(",
    "decodeURIComponent(",
)

# JS patterns that redirect/reload the page — bot check gates that need a
# real browser to pass (cookie-set-then-reload, navigator.webdriver checks,
# window.location assignments, meta refresh).
_JS_REDIRECT_MARKERS = (
    "location.reload(",
    "location.href",
    "location.replace(",
    "document.location",
    "window.location",
    'http-equiv="refresh"',
    "http-equiv='refresh'",
)

# Content types we capture response bodies for (text-based resources)
_CAPTURABLE_CONTENT_TYPES = (
    "text/",
    "application/javascript",
    "application/x-javascript",
    "application/json",
    "application/xml",
    "application/xhtml",
    "application/x-php",
    "application/x-httpd-php",
)

# Content types to skip (binary resources)
_SKIP_CONTENT_TYPES = (
    "image/",
    "font/",
    "audio/",
    "video/",
    "application/octet-stream",
    "application/zip",
    "application/pdf",
    "application/woff",
    "application/x-font",
)


def is_js_loader(filepath: Path, max_check_size: int = 50_000) -> bool:
    """Detect if a downloaded HTML file is a JS-only loader with no real content.

    Returns True when the file has JS execution markers (eval, atob, etc.)
    or JS redirect/reload patterns (bot check gates) but no ``<form>``,
    ``<input>``, or credential fields — indicating a multi-stage page that
    needs browser rendering to reveal the actual phishing content.
    """
    try:
        content = filepath.read_text(
            encoding="utf-8", errors="ignore",
        )[:max_check_size]
    except Exception:
        return False

    lower = content.lower()

    # Must look like HTML/JS (not a zip/binary that httpx mis-saved)
    if not any(tag in lower for tag in ("<html", "<script", "<!doctype")):
        return False

    # Needs JS execution/deobfuscation markers OR JS redirect/reload patterns
    has_js_loader = any(m.lower() in lower for m in _JS_LOADER_MARKERS)
    has_js_redirect = any(m.lower() in lower for m in _JS_REDIRECT_MARKERS)
    if not has_js_loader and not has_js_redirect:
        return False

    # Lacks real HTML content (forms, inputs, credential fields)
    has_form = any(
        tag in lower
        for tag in ("<form", "<input", 'type="password"', "type='password'")
    )
    return not has_form


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


def _sanitize_filename(url: str, index: int) -> str:
    """Convert a URL into a safe filename for saving captured resources.

    Preserves the original file extension where possible.  Falls back to
    an index-based name for URLs that don't map to a clean filename.
    """
    parsed = urlparse(url)
    path = parsed.path.rstrip("/")

    if path and path != "/":
        # Use the last path component
        name = path.rsplit("/", 1)[-1]
        # Strip query params from the name but keep extension
        name = re.sub(r"[?#].*$", "", name)
        # Sanitize: keep only safe characters
        name = re.sub(r"[^\w.\-]", "_", name)
        if len(name) > 80:
            name = name[:80]
        if name and name != "_":
            return f"{index:03d}_{name}"

    # Fallback: use domain + index
    domain = parsed.hostname or "unknown"
    return f"{index:03d}_{domain}"


def _should_capture_body(content_type: str) -> bool:
    """Check if a response's content type is text-based and worth capturing."""
    ct = content_type.lower()
    # Skip binary resources
    if any(ct.startswith(skip) for skip in _SKIP_CONTENT_TYPES):
        return False
    # Capture text-based resources
    if any(cap in ct for cap in _CAPTURABLE_CONTENT_TYPES):
        return True
    # Unknown content type — skip to be safe (avoid saving binary blobs)
    return False


async def _handle_ipinfo_route(route) -> None:
    """Intercept ipinfo.io requests used by cloaking gates.

    Returns a spoofed residential-looking response so IP-based cloaking
    checks pass.  The phishing page sees a clean ISP name instead of a
    cloud provider, allowing the real content to render.
    """
    import json as _json

    spoofed = {
        "ip": "73.162.19.42",
        "hostname": "c-73-162-19-42.hsd1.ca.comcast.net",
        "city": "San Jose",
        "region": "California",
        "country": "US",
        "loc": "37.3382,-121.8863",
        "org": "AS7922 Comcast Cable Communications, LLC",
        "postal": "95113",
        "timezone": "America/Los_Angeles",
    }
    logger.debug("Intercepted ipinfo request: %s", route.request.url)
    await route.fulfill(
        status=200,
        content_type="application/json",
        body=_json.dumps(spoofed),
    )


async def _take_screenshot(page, screenshots_dir: Path, stage: str) -> Path | None:
    """Take a screenshot and save it with a stage label."""
    try:
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        filepath = screenshots_dir / f"{stage}.png"
        await page.screenshot(path=str(filepath), full_page=True)
        logger.info("Screenshot saved: %s (%d bytes)", filepath.name, filepath.stat().st_size)
        return filepath
    except Exception as e:
        logger.debug("Screenshot failed at stage %s: %s", stage, e)
        return None


async def _async_browser_download(
    url: str,
    dest_dir: str,
    timeout: int = 60,
    turnstile_timeout: int = 30,
) -> tuple[Path | None, str, str | None]:
    """Internal async implementation of the browser download.

    Captures ALL network responses (JS, PHP, CSS, XHR, fetch, WebSocket
    upgrades) in addition to the final rendered page.  Saves:

    - ``page.html`` — rendered DOM after all stages
    - ``_browser_resources/<NNN>_<filename>`` — captured sub-resources
    - ``_screenshots/<stage>.png`` — screenshots at each page stage
    - ``requests.json`` — full network request/response log
    """
    try:
        from camoufox.async_api import AsyncCamoufox
    except ImportError:
        return None, "camoufox not installed (pip install phishkiller[browser])", None

    dest_path = Path(dest_dir)
    dest_path.mkdir(parents=True, exist_ok=True)
    resources_dir = dest_path / "_browser_resources"
    screenshots_dir = dest_path / "_screenshots"

    # Network capture state
    network_log: list[dict] = []
    captured_responses: list[dict] = []
    response_counter = 0
    nav_start_time = 0.0

    async def _on_request(request):
        """Log every outgoing request."""
        nonlocal nav_start_time
        elapsed = time.monotonic() - nav_start_time if nav_start_time else 0
        network_log.append({
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
            "headers": dict(request.headers),
            "timestamp": round(elapsed, 3),
            "type": "request",
        })

    async def _on_response(response):
        """Capture response metadata and body for text-based resources."""
        nonlocal response_counter, nav_start_time
        elapsed = time.monotonic() - nav_start_time if nav_start_time else 0

        entry = {
            "url": response.url,
            "status": response.status,
            "content_type": response.headers.get("content-type", ""),
            "headers": dict(response.headers),
            "timestamp": round(elapsed, 3),
            "type": "response",
        }
        network_log.append(entry)

        # Capture body for text-based resources
        ct = response.headers.get("content-type", "")
        if _should_capture_body(ct):
            try:
                body = await response.body()
                if body and len(body) < 2 * 1024 * 1024:  # 2MB cap per resource
                    response_counter += 1
                    captured_responses.append({
                        "url": response.url,
                        "status": response.status,
                        "content_type": ct,
                        "body": body,
                        "index": response_counter,
                    })
            except Exception:
                pass  # Response may be closed/redirected

    try:
        async with AsyncCamoufox(
            headless="virtual",
            humanize=True,
            block_webrtc=True,
            disable_coop=True,
            i_know_what_im_doing=True,
            geoip=True,
        ) as browser:
            page = await browser.new_page(ignore_https_errors=True)

            # Set a realistic navigation timeout
            page.set_default_timeout(timeout * 1000)
            page.set_default_navigation_timeout(timeout * 1000)

            # Inject stealth JS before any page scripts run
            await page.add_init_script(_STEALTH_JS)

            # Register network interception handlers BEFORE navigation
            page.on("request", _on_request)
            page.on("response", _on_response)

            # Intercept IP-info lookups used by cloaking gates.
            await page.route("**/ipinfo.io/**", _handle_ipinfo_route)

            start_time = asyncio.get_event_loop().time()
            nav_start_time = time.monotonic()

            is_file_url = url.startswith("file://")
            logger.info("Browser navigating to %s", url)
            response = await page.goto(url, wait_until="domcontentloaded")

            if not response and not is_file_url:
                return None, "Browser navigation returned no response", None

            # Give JS deobfuscation / eval layers time to execute
            await asyncio.sleep(random.uniform(3.0, 5.0))

            # Screenshot: landing page (stage 1 — what the browser first shows)
            await _take_screenshot(page, screenshots_dir, "01_landing")

            # Wait for Turnstile widget to auto-resolve if present,
            # with a configurable timeout to prevent hanging forever.
            turnstile_result = await _wait_for_turnstile(
                page, timeout=turnstile_timeout,
            )

            if turnstile_result == "timeout":
                # Turnstile escalated to interactive — try fresh context
                logger.info(
                    "Turnstile timed out after %ds, attempting fresh context",
                    turnstile_timeout,
                )
                # Close current page, open fresh one (new CF session)
                await page.close()
                page = await browser.new_page(ignore_https_errors=True)
                page.set_default_timeout(timeout * 1000)
                page.set_default_navigation_timeout(timeout * 1000)
                await page.add_init_script(_STEALTH_JS)

                # Re-register network handlers on new page
                page.on("request", _on_request)
                page.on("response", _on_response)
                await page.route("**/ipinfo.io/**", _handle_ipinfo_route)

                nav_start_time = time.monotonic()
                response = await page.goto(url, wait_until="domcontentloaded")
                await asyncio.sleep(random.uniform(3.0, 5.0))

                # Second attempt at Turnstile (fresh session = managed mode)
                turnstile_result = await _wait_for_turnstile(page, timeout=turnstile_timeout)

            # Screenshot: after Turnstile/bot check (stage 2) — only if Turnstile was present
            if turnstile_result != "absent":
                await _take_screenshot(page, screenshots_dir, "02_bot_check")

            # Simulate minimal human behavior to pass behavioral checks
            await _simulate_human_behavior(page)

            # Wait for any post-challenge redirect or content load.
            # Use asyncio.wait_for to enforce a hard deadline — Playwright's
            # wait_for_load_state("networkidle") can hang indefinitely when
            # Turnstile/CAPTCHA scripts keep polling.
            try:
                await asyncio.wait_for(
                    page.wait_for_load_state("networkidle"),
                    timeout=15,
                )
            except (asyncio.TimeoutError, Exception):
                pass

            # Give anti-analysis JS time to run its scoring
            await asyncio.sleep(random.uniform(2.0, 4.0))

            # Attempt to bypass custom anti-bot verification gates
            elapsed = asyncio.get_event_loop().time() - start_time
            timeout_remaining = timeout - elapsed
            if timeout_remaining > 15:
                gate_found = await _attempt_bot_gate_bypass(
                    page, timeout_remaining,
                )
                if gate_found:
                    logger.info(
                        "Bot gate interaction completed, final URL: %s",
                        page.url,
                    )

            # Wait for final content to settle
            try:
                await asyncio.wait_for(
                    page.wait_for_load_state("networkidle"),
                    timeout=10,
                )
            except (asyncio.TimeoutError, Exception):
                pass
            await asyncio.sleep(random.uniform(1.0, 2.0))

            # Screenshot: final phishing page (stage 3)
            await _take_screenshot(page, screenshots_dir, "03_phish")

            # Capture final page content
            content = await page.content()
            final_url = page.url

            if not content or len(content) < 100:
                return None, "Browser captured empty or minimal page content", None

            # Save HTML to disk
            filename = "page.html"
            filepath = dest_path / filename
            filepath.write_text(content, encoding="utf-8")

            # Save captured sub-resources
            saved_resources = 0
            if captured_responses:
                resources_dir.mkdir(parents=True, exist_ok=True)
                for resp in captured_responses:
                    # Skip the main document (already saved as page.html)
                    if resp["url"] == final_url or resp["url"] == url:
                        continue
                    try:
                        res_filename = _sanitize_filename(
                            resp["url"], resp["index"],
                        )
                        # Add appropriate extension based on content type
                        ct = resp["content_type"].lower()
                        if "javascript" in ct and not res_filename.endswith(".js"):
                            res_filename += ".js"
                        elif "json" in ct and not res_filename.endswith(".json"):
                            res_filename += ".json"
                        elif "css" in ct and not res_filename.endswith(".css"):
                            res_filename += ".css"
                        elif "html" in ct and not any(
                            res_filename.endswith(e) for e in (".html", ".htm", ".php")
                        ):
                            res_filename += ".html"

                        res_path = resources_dir / res_filename
                        body = resp["body"]
                        if isinstance(body, bytes):
                            try:
                                res_path.write_text(
                                    body.decode("utf-8", errors="replace"),
                                    encoding="utf-8",
                                )
                            except Exception:
                                res_path.write_bytes(body)
                        else:
                            res_path.write_text(str(body), encoding="utf-8")
                        saved_resources += 1
                    except Exception as e:
                        logger.debug(
                            "Failed to save resource %s: %s", resp["url"], e,
                        )

            # Save network log as requests.json
            try:
                requests_path = dest_path / "requests.json"
                requests_path.write_text(
                    json.dumps(network_log, indent=2, default=str),
                    encoding="utf-8",
                )
            except Exception as e:
                logger.debug("Failed to save requests.json: %s", e)

            logger.info(
                "Browser captured %d bytes from %s (final URL: %s, "
                "%d sub-resources, %d network events)",
                len(content), url, final_url,
                saved_resources, len(network_log),
            )
            return filepath, "ok", final_url

    except Exception as e:
        logger.error("Browser download failed for %s: %s", url, e)
        return None, f"Browser error: {type(e).__name__}: {e}", None


async def _wait_for_turnstile(page, timeout: int = 30) -> str:
    """Wait for Cloudflare Turnstile CAPTCHA and attempt to solve it.

    Returns:
        "solved" — Turnstile was present and resolved
        "absent" — No Turnstile widget on page
        "timeout" — Turnstile present but not solved within timeout
        "error" — Exception during handling
    """
    try:
        # Check if page has a Turnstile widget at all
        has_turnstile = await page.evaluate("""
            () => !!document.querySelector('.cf-turnstile, [data-sitekey]')
        """)
        if not has_turnstile:
            return "absent"

        logger.info("Turnstile widget found on page")

        # Give managed-mode a few seconds to auto-resolve
        await asyncio.sleep(random.uniform(2.5, 4.0))

        # Check if already solved (response token populated)
        if await _turnstile_solved(page):
            logger.info("Turnstile auto-resolved (managed mode)")
            await _wait_after_turnstile(page)
            return "solved"

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
                click_x = box["x"] + box["width"] / 9
                click_y = box["y"] + box["height"] / 2
                logger.info(
                    "Clicking Turnstile iframe at (%.0f, %.0f)",
                    click_x, click_y,
                )
                await page.mouse.click(click_x, click_y)
                await asyncio.sleep(random.uniform(1.5, 3.0))
        else:
            widget = await page.query_selector(
                ".cf-turnstile, [data-sitekey]"
            )
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
                    logger.warning(
                        "Turnstile widget found but has no bounding box — "
                        "will poll for auto-resolve",
                    )
            else:
                logger.warning(
                    "Turnstile widget present but no clickable element found — "
                    "will poll for auto-resolve",
                )

        # Poll for the response token with a hard timeout
        poll_deadline = asyncio.get_event_loop().time() + timeout
        while asyncio.get_event_loop().time() < poll_deadline:
            if await _turnstile_solved(page):
                logger.info("Turnstile solved after click")
                await _wait_after_turnstile(page)
                return "solved"
            await asyncio.sleep(1.0)

        logger.warning(
            "Turnstile not solved within %ds timeout", timeout,
        )
        return "timeout"

    except Exception as e:
        logger.warning("Turnstile handling error: %s", e)
        return "error"


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
        await asyncio.wait_for(
            page.wait_for_load_state("networkidle"),
            timeout=10,
        )
    except (asyncio.TimeoutError, Exception):
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


async def _detect_bot_gate(page) -> dict | None:
    """Detect common anti-bot verification gates on the page.

    Scans for:
    1. Buttons/links with verify/check text (traditional gates)
    2. Div/span checkbox-style clickables near verification text
       (e.g. "Prove you are human", "Verify you're not a bot")
    3. Hidden challenge form fields with a single prominent clickable

    Returns gate metadata or None if no gate detected.
    """
    try:
        return await page.evaluate("""
            () => {
                function makeSelector(el) {
                    if (el.id) return '#' + CSS.escape(el.id);
                    if (el.className && typeof el.className === 'string') {
                        const cls = el.className.trim().split(/\\s+/)[0];
                        if (cls) return el.tagName.toLowerCase() + '.' + CSS.escape(cls);
                    }
                    return el.tagName.toLowerCase();
                }

                // --- Strategy 1: clickable elements with verify text ---
                const candidates = [
                    ...document.querySelectorAll(
                        'button, a, input[type="button"], input[type="submit"], '
                        + '[role="button"], [onclick], div[class*="btn"], span[class*="btn"]'
                    )
                ];

                const verifyPatterns = [
                    /^verify$/i, /^verify now$/i, /^verify you are human$/i,
                    /^check$/i, /^continue$/i, /^i'?m not a robot$/i,
                    /^press & hold$/i, /^click to continue$/i,
                    /^confirm$/i, /^human verification$/i,
                    /^click to verify/i, /^verify your browser/i,
                ];

                for (const el of candidates) {
                    const text = (el.textContent || el.value || '').trim();
                    if (text.length > 60 || text.length < 3) continue;
                    for (const pat of verifyPatterns) {
                        if (pat.test(text)) {
                            return {
                                type: 'verify_button',
                                selector: makeSelector(el),
                                text: text,
                                tagName: el.tagName,
                            };
                        }
                    }
                }

                // --- Strategy 2: div/span checkbox gates ---
                const pageText = document.body ? document.body.innerText : '';
                const gateTextPats = [
                    /prove you are human/i,
                    /verify you'?re not a bot/i,
                    /confirm you'?re real/i,
                    /human check/i,
                    /bot protection/i,
                    /security check/i,
                    /checking.{0,10}browser/i,
                ];
                const hasGateText = gateTextPats.some(p => p.test(pageText));

                if (hasGateText) {
                    const clickables = [...document.querySelectorAll(
                        'div[class*="check"], div[class*="target"], '
                        + 'div[class*="circle"], div[class*="square"], '
                        + 'span[class*="check"], span[class*="target"], '
                        + '[style*="cursor: pointer"], [style*="cursor:pointer"]'
                    )].filter(el => {
                        const r = el.getBoundingClientRect();
                        return r.width >= 12 && r.width <= 60
                            && r.height >= 12 && r.height <= 60
                            && r.width > 0 && r.height > 0;
                    });

                    if (clickables.length === 0) {
                        const containers = document.querySelectorAll(
                            '[class*="verif"], [class*="captcha"], [class*="check"], '
                            + '[class*="human"], [class*="premium-card"]'
                        );
                        for (const container of containers) {
                            const kids = container.querySelectorAll('div, span');
                            for (const kid of kids) {
                                const cs = window.getComputedStyle(kid);
                                const r = kid.getBoundingClientRect();
                                if (cs.cursor === 'pointer'
                                    && r.width >= 12 && r.width <= 60
                                    && r.height >= 12 && r.height <= 60) {
                                    clickables.push(kid);
                                }
                            }
                        }
                    }

                    if (clickables.length > 0) {
                        const el = clickables[0];
                        return {
                            type: 'checkbox_gate',
                            selector: makeSelector(el),
                            text: pageText.substring(0, 80).trim(),
                            tagName: el.tagName,
                            hasAutoSubmitForm: !!document.querySelector(
                                'form[method] input[type="hidden"]'
                            ),
                        };
                    }
                }

                // --- Strategy 3: hidden challenge fields with a button ---
                const challengeFields = document.querySelectorAll(
                    'input[type="hidden"][name*="nonce"], input[type="hidden"][name*="token"], '
                    + 'input[type="hidden"][name*="pow"], form[style*="display:none"]'
                );
                if (challengeFields.length > 0) {
                    const btns = [...document.querySelectorAll(
                        'button, input[type="submit"], [role="button"]'
                    )].filter(b => {
                        const r = b.getBoundingClientRect();
                        return r.width > 0 && r.height > 0;
                    });
                    if (btns.length >= 1) {
                        const el = btns[0];
                        return {
                            type: 'challenge_form',
                            selector: makeSelector(el),
                            text: (el.textContent || el.value || '').trim(),
                            tagName: el.tagName,
                        };
                    }
                }

                // --- Strategy 4: POST form with hidden input + gate page text ---
                if (hasGateText) {
                    const form = document.querySelector('form[method]');
                    const hiddenInput = form
                        ? form.querySelector('input[type="hidden"]')
                        : null;
                    if (form && hiddenInput) {
                        const allDivs = [...document.querySelectorAll('div, span')];
                        for (const el of allDivs) {
                            const cs = window.getComputedStyle(el);
                            const r = el.getBoundingClientRect();
                            if (cs.cursor === 'pointer'
                                && r.width >= 12 && r.width <= 60
                                && r.height >= 12 && r.height <= 60) {
                                return {
                                    type: 'checkbox_gate',
                                    selector: makeSelector(el),
                                    text: pageText.substring(0, 80).trim(),
                                    tagName: el.tagName,
                                    hasAutoSubmitForm: true,
                                };
                            }
                        }
                    }
                }

                return null;
            }
        """)
    except Exception as e:
        logger.debug("Bot gate detection error: %s", e)
        return None


async def _build_mouse_track(page) -> None:
    """Generate realistic mouse movement to satisfy movement-tracking gates."""
    try:
        viewport = page.viewport_size or {"width": 1280, "height": 800}
        w, h = viewport["width"], viewport["height"]

        cx = random.randint(int(w * 0.2), int(w * 0.5))
        cy = random.randint(int(h * 0.2), int(h * 0.5))
        await page.mouse.move(cx, cy)
        await asyncio.sleep(random.uniform(0.3, 0.6))

        for _ in range(random.randint(8, 12)):
            cx += random.randint(-120, 120)
            cy += random.randint(-80, 80)
            cx = max(10, min(cx, w - 10))
            cy = max(10, min(cy, h - 10))
            await page.mouse.move(cx, cy)
            await asyncio.sleep(random.uniform(0.05, 0.2))

        await page.mouse.wheel(0, random.randint(30, 120))
        await asyncio.sleep(random.uniform(0.2, 0.5))

    except Exception:
        pass


async def _attempt_bot_gate_bypass(page, timeout_remaining: float) -> bool:
    """Detect and attempt to bypass a custom anti-bot verification gate.

    Returns True if a gate was detected and interaction attempted.
    """
    gate = await _detect_bot_gate(page)
    if not gate:
        return False

    logger.info(
        "Bot gate detected: type=%s text=%r selector=%s",
        gate["type"], gate["text"], gate["selector"],
    )

    # Phase 1: Build mouse movement track
    await _build_mouse_track(page)

    # Phase 2: Click the gate element with natural mouse approach
    pre_click_url = page.url
    try:
        element = await page.query_selector(gate["selector"])
        if not element:
            if gate["type"] == "verify_button":
                for candidate in await page.query_selector_all(
                    "button, [role='button'], a"
                ):
                    text = (await candidate.text_content() or "").strip()
                    if text and text.lower() == gate["text"].lower():
                        element = candidate
                        break

        if not element:
            logger.warning("Bot gate element not found after detection")
            return True

        box = await element.bounding_box()
        if box:
            viewport = page.viewport_size or {"width": 1280, "height": 800}
            sx = random.randint(
                int(viewport["width"] * 0.3), int(viewport["width"] * 0.7),
            )
            sy = random.randint(
                int(viewport["height"] * 0.3), int(viewport["height"] * 0.6),
            )
            tx = box["x"] + box["width"] / 2
            ty = box["y"] + box["height"] / 2

            steps = random.randint(3, 5)
            for i in range(1, steps + 1):
                frac = i / steps
                mx = sx + (tx - sx) * frac + random.uniform(-8, 8)
                my = sy + (ty - sy) * frac + random.uniform(-5, 5)
                await page.mouse.move(mx, my)
                await asyncio.sleep(random.uniform(0.04, 0.12))

            await asyncio.sleep(random.uniform(0.15, 0.4))
            await page.mouse.click(tx, ty)
        else:
            await element.click()

        logger.info("Clicked bot gate element: type=%s", gate["type"])

    except Exception as e:
        logger.warning("Failed to click bot gate element: %s", e)
        return True

    # Phase 3: Wait for resolution
    if gate.get("hasAutoSubmitForm") or gate["type"] == "checkbox_gate":
        await _wait_for_form_submit(page, pre_click_url, timeout_remaining)
    else:
        await _wait_for_gate_resolution(page, pre_click_url, timeout_remaining)

    return True


async def _wait_for_gate_resolution(
    page, pre_click_url: str, timeout_remaining: float,
) -> None:
    """Wait for bot gate challenge resolution and subsequent navigation."""
    gate_timeout = min(30.0, max(5.0, timeout_remaining - 10.0))
    logger.info("Waiting up to %.0fs for bot gate resolution", gate_timeout)

    try:
        try:
            await page.wait_for_url(
                lambda url: url != pre_click_url,
                timeout=gate_timeout * 1000,
            )
            logger.info("Bot gate navigated to %s", page.url)
            try:
                await asyncio.wait_for(
                    page.wait_for_load_state("networkidle"),
                    timeout=10,
                )
            except (asyncio.TimeoutError, Exception):
                pass
            await asyncio.sleep(random.uniform(1.5, 3.0))
            return
        except Exception:
            pass

        gate_gone = await page.evaluate("""
            () => {
                const btns = document.querySelectorAll(
                    'button, input[type="submit"], [role="button"]'
                );
                const pat = /verify|check|continue|not a robot|confirm/i;
                for (const b of btns) {
                    if (pat.test(b.textContent || b.value || '')) return false;
                }
                return true;
            }
        """)
        if gate_gone:
            logger.info("Bot gate button disappeared — gate likely passed")
            await asyncio.sleep(random.uniform(1.0, 2.0))
        else:
            logger.warning(
                "Bot gate button still present after %.0fs — PoW may have "
                "failed or timed out",
                gate_timeout,
            )

    except Exception as e:
        logger.warning("Error waiting for gate resolution: %s", e)


async def _wait_for_form_submit(
    page, pre_click_url: str, timeout_remaining: float,
) -> None:
    """Wait for a checkbox gate's auto-submit form to fire and navigate."""
    form_timeout = min(15.0, max(5.0, timeout_remaining - 10.0))
    logger.info(
        "Waiting up to %.0fs for checkbox gate form submission", form_timeout,
    )

    try:
        await asyncio.sleep(4.0)

        if page.url != pre_click_url:
            logger.info("Form POST navigated to %s", page.url)
            try:
                await asyncio.wait_for(
                    page.wait_for_load_state("networkidle"),
                    timeout=10,
                )
            except (asyncio.TimeoutError, Exception):
                pass
            await asyncio.sleep(random.uniform(1.5, 3.0))
            return

        try:
            await asyncio.wait_for(
                page.wait_for_load_state("networkidle"),
                timeout=form_timeout,
            )
        except (asyncio.TimeoutError, Exception):
            pass

        await asyncio.sleep(random.uniform(2.0, 4.0))

        logger.info(
            "Checkbox gate form submitted, final URL: %s", page.url,
        )

    except Exception as e:
        logger.warning("Error during form submit wait: %s", e)


def browser_download(
    url: str,
    dest_dir: str,
    timeout: int = 60,
    turnstile_timeout: int = 30,
) -> tuple[Path | None, str, str | None]:
    """Download a URL using a stealth browser (Camoufox).

    Synchronous wrapper around the async implementation for use in
    Celery tasks.  Returns ``(filepath, reason, final_url)`` — the
    final URL is the browser's location after all redirects/gates.

    In addition to page.html, saves:
    - ``_browser_resources/`` — captured JS, PHP, CSS, XHR responses
    - ``_screenshots/`` — screenshots at each page stage
    - ``requests.json`` — full network request/response log
    """
    if not _is_available():
        return None, "camoufox not installed (pip install phishkiller[browser])", None

    # Hard wall-clock deadline: timeout + turnstile_timeout + 30s buffer.
    # This prevents the async function from hanging indefinitely when
    # networkidle waits never resolve (e.g., Turnstile keeps polling).
    hard_timeout = timeout + turnstile_timeout + 30

    start = time.monotonic()
    try:
        loop = asyncio.new_event_loop()
        coro = _async_browser_download(url, dest_dir, timeout, turnstile_timeout)
        result = loop.run_until_complete(
            asyncio.wait_for(coro, timeout=hard_timeout)
        )
        elapsed = time.monotonic() - start
        logger.info("Browser download completed in %.1fs", elapsed)
        return result
    except asyncio.TimeoutError:
        elapsed = time.monotonic() - start
        logger.error(
            "Browser download hard timeout after %.1fs (limit %ds)",
            elapsed, hard_timeout,
        )
        return None, f"Browser hard timeout after {hard_timeout}s", None
    except Exception as e:
        elapsed = time.monotonic() - start
        logger.error("Browser download wrapper failed after %.1fs: %s", elapsed, e)
        return None, f"Browser error: {type(e).__name__}: {e}", None
    finally:
        loop.close()
