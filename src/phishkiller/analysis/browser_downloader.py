"""Stealth browser downloader for Cloudflare-protected phishing pages.

Uses Camoufox (anti-detect Firefox) to bypass bot protection, Cloudflare
Turnstile CAPTCHAs, custom anti-bot verification gates, and anti-analysis
JavaScript.  Falls back gracefully when the ``camoufox`` package is not
installed.

Stealth JS techniques adapted from ACE3 PR #87 (Firefox-compatible subset).

Requires the optional ``browser`` dependency group::

    pip install phishkiller[browser]
"""

import asyncio
import logging
import random
import time
from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Stealth JS — injected via page.add_init_script() before navigation.
# Covers signals that Camoufox doesn't handle natively: WebGL renderer
# strings in Docker, screen.availHeight in Xvfb, matchMedia for virtual
# displays, and generic bot-marker properties that custom gates check.
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


def is_js_loader(filepath: Path, max_check_size: int = 50_000) -> bool:
    """Detect if a downloaded HTML file is a JS-only loader with no real content.

    Returns True when the file has JS execution markers (eval, atob, etc.)
    but no ``<form>``, ``<input>``, or credential fields — indicating a
    multi-stage loader that needs browser rendering to reveal the actual
    phishing page.
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

    # Needs JS execution/deobfuscation markers
    if not any(m.lower() in lower for m in _JS_LOADER_MARKERS):
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

            # Inject stealth JS before any page scripts run
            await page.add_init_script(_STEALTH_JS)

            # Intercept IP-info lookups used by cloaking gates.
            # Many phishing kits fetch ipinfo.io/json and redirect to a
            # dud site if the visitor's org matches a cloud provider.
            # Return a clean residential-looking response so the page
            # shows its real content.
            await page.route("**/ipinfo.io/**", _handle_ipinfo_route)

            start_time = asyncio.get_event_loop().time()

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
            try:
                await page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
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
                // These use styled div checkboxes near text like "Prove you
                // are human".  The clickable element is a small div with
                // cursor:pointer, and the label is a sibling span/div.
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
                    // Look for small clickable div/span elements (checkboxes)
                    const clickables = [...document.querySelectorAll(
                        'div[class*="check"], div[class*="target"], '
                        + 'div[class*="circle"], div[class*="square"], '
                        + 'span[class*="check"], span[class*="target"], '
                        + '[style*="cursor: pointer"], [style*="cursor:pointer"]'
                    )].filter(el => {
                        const r = el.getBoundingClientRect();
                        // Checkbox-like: small, roughly square, visible
                        return r.width >= 12 && r.width <= 60
                            && r.height >= 12 && r.height <= 60
                            && r.width > 0 && r.height > 0;
                    });

                    // Also check computed cursor style for elements
                    // inside verification-related containers
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
                // Some gates have a hidden form that auto-submits after click,
                // with the clickable being a generic div
                if (hasGateText) {
                    const form = document.querySelector('form[method]');
                    const hiddenInput = form
                        ? form.querySelector('input[type="hidden"]')
                        : null;
                    if (form && hiddenInput) {
                        // Find the most prominent clickable in the page
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
    """Generate realistic mouse movement to satisfy movement-tracking gates.

    Produces 8-12 distinct mousemove events with natural timing and curved
    paths.  Gates typically hash mouse positions; this ensures the tracking
    buffer is well-populated before any verify click.
    """
    try:
        viewport = page.viewport_size or {"width": 1280, "height": 800}
        w, h = viewport["width"], viewport["height"]

        # Start from a random position
        cx = random.randint(int(w * 0.2), int(w * 0.5))
        cy = random.randint(int(h * 0.2), int(h * 0.5))
        await page.mouse.move(cx, cy)
        await asyncio.sleep(random.uniform(0.3, 0.6))

        # 8-12 movements with natural-looking curves
        for _ in range(random.randint(8, 12)):
            cx += random.randint(-120, 120)
            cy += random.randint(-80, 80)
            cx = max(10, min(cx, w - 10))
            cy = max(10, min(cy, h - 10))
            await page.mouse.move(cx, cy)
            await asyncio.sleep(random.uniform(0.05, 0.2))

        # Small scroll for extra interaction data
        await page.mouse.wheel(0, random.randint(30, 120))
        await asyncio.sleep(random.uniform(0.2, 0.5))

    except Exception:
        pass


async def _attempt_bot_gate_bypass(page, timeout_remaining: float) -> bool:
    """Detect and attempt to bypass a custom anti-bot verification gate.

    Supports two gate styles:
    1. Button gates — click a "Verify Now" button, wait for PoW + redirect
    2. Checkbox gates — click a styled div checkbox, wait for the page's
       JS to auto-submit a hidden form, then capture the post-redirect content

    Returns True if a gate was detected and interaction attempted.
    """
    gate = await _detect_bot_gate(page)
    if not gate:
        return False

    logger.info(
        "Bot gate detected: type=%s text=%r selector=%s",
        gate["type"], gate["text"], gate["selector"],
    )

    # Phase 1: Build mouse movement track — many gates require mousemove
    # data before they'll accept a verify click.
    await _build_mouse_track(page)

    # Phase 2: Click the gate element with natural mouse approach
    pre_click_url = page.url
    try:
        element = await page.query_selector(gate["selector"])
        if not element:
            # Fallback for button-type gates: find by visible text
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
            # Start from a random spot and approach the element with curve
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

    # Phase 3: Wait for resolution — differs by gate type
    if gate.get("hasAutoSubmitForm") or gate["type"] == "checkbox_gate":
        # Checkbox gates auto-submit a hidden form after a short delay
        # (typically 1.5-3s for the "Verified" animation, then form.submit())
        await _wait_for_form_submit(page, pre_click_url, timeout_remaining)
    else:
        # Button gates do PoW + redirect
        await _wait_for_gate_resolution(page, pre_click_url, timeout_remaining)

    return True


async def _wait_for_gate_resolution(
    page, pre_click_url: str, timeout_remaining: float,
) -> None:
    """Wait for bot gate challenge resolution and subsequent navigation.

    After clicking verify, the gate typically fetches a nonce, runs a
    SHA-256 PoW in WebWorkers, POSTs the solution, then auto-submits a
    form which sets a cookie and redirects to the real phishing page.
    """
    gate_timeout = min(30.0, max(5.0, timeout_remaining - 10.0))
    logger.info("Waiting up to %.0fs for bot gate resolution", gate_timeout)

    try:
        # Primary: wait for URL change (redirect after PoW success)
        try:
            await page.wait_for_url(
                lambda url: url != pre_click_url,
                timeout=gate_timeout * 1000,
            )
            logger.info("Bot gate navigated to %s", page.url)
            try:
                await page.wait_for_load_state("networkidle", timeout=10000)
            except Exception:
                pass
            await asyncio.sleep(random.uniform(1.5, 3.0))
            return
        except Exception:
            pass

        # Fallback: check if page content changed (SPA-style gate)
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
    """Wait for a checkbox gate's auto-submit form to fire and navigate.

    After clicking the checkbox, the gate JS typically:
    1. Shows a spinner for 1.5-2s
    2. Displays "Verified" for ~1s
    3. Calls form.submit() which POSTs to the same URL
    4. Server responds with a redirect or sets a cookie + new content

    We wait for the form submission (navigation event) and then capture
    the post-submit page content.
    """
    form_timeout = min(15.0, max(5.0, timeout_remaining - 10.0))
    logger.info(
        "Waiting up to %.0fs for checkbox gate form submission", form_timeout,
    )

    try:
        # Wait for navigation triggered by form.submit()
        # The form typically auto-submits 2-4s after the click.
        # Playwright async API uses expect_navigation() context manager,
        # but since the click already happened, we use wait_for_url or
        # wait_for_load_state to detect the POST navigation.

        # First, give the gate JS time to show "Verified" and fire submit
        # (typically 1.5s animation + 3s delay before form.submit())
        await asyncio.sleep(4.0)

        # Check if URL changed (form POST may redirect)
        if page.url != pre_click_url:
            logger.info("Form POST navigated to %s", page.url)
            try:
                await page.wait_for_load_state(
                    "networkidle", timeout=10000,
                )
            except Exception:
                pass
            await asyncio.sleep(random.uniform(1.5, 3.0))
            return

        # URL didn't change — form may have POSTed to same URL.
        # Wait for the response to load (new page content from POST).
        try:
            await page.wait_for_load_state(
                "networkidle", timeout=form_timeout * 1000,
            )
        except Exception:
            pass

        # Give post-submit content time to settle
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
