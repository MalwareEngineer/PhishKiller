# Cloudflare Turnstile Bypass — Implementation Writeup

## Background

Modern phishing kits increasingly deploy behind Cloudflare's free tier, using Turnstile CAPTCHAs and bot-detection JavaScript as an anti-researcher shield. Our httpx-based downloader gets `ConnectError` on these pages — Cloudflare's TLS fingerprinting rejects the connection before any HTTP exchange occurs. This makes us blind to a growing class of kits.

The test target was `https://outlookbenefit.designwithcertainty.de/3jplt/` — a multi-stage Microsoft credential phishing kit with Cloudflare Turnstile gating.

---

## The Three-Stage Phishing Kit Architecture

What makes this class of kit particularly challenging is its multi-stage rendering architecture:

### Stage 1: JS Loader (9.7KB)
The raw HTML served by the web server. Contains a PRNG-seeded cipher that decodes the next stage via `eval()`. This is all httpx captures — a useless blob of obfuscated JavaScript with zero phishing indicators.

- **YARA matches**: 0
- **IOCs extracted**: 0
- **Phishing content**: None visible

### Stage 2: Decoded HTML with Turnstile Gate
After the JS eval layer executes, the DOM contains a Cloudflare Turnstile widget (`<div class="cf-turnstile" data-sitekey="...">`) and a second encrypted payload blob. The page loads `challenges.cloudflare.com/turnstile/v0/api.js`, which renders a cross-origin iframe with the CAPTCHA challenge.

- **YARA matches**: `PhishKit_Cloudflare_Turnstile_Gate`
- **IOCs extracted**: Turnstile sitekey, Cloudflare challenge URLs

### Stage 3: Full Credential Form (354KB)
The final rendered Microsoft credential harvester. Contains login forms, Microsoft branding, 83 login-related references, 33 Microsoft-specific references, input fields for email/password, and exfiltration JavaScript.

- **YARA matches**: `PhishKit_Microsoft_Branded_Page`
- **IOCs extracted**: C2 URLs, exfil endpoints, email patterns

The gap between Stage 1 (what httpx gets) and Stage 3 (what a real browser sees) is the entire intelligence value of the kit.

---

## Implementation

### Browser Engine Selection: Camoufox

We evaluated Playwright+stealth, Puppeteer+stealth, undetected-chromedriver, and Camoufox. Camoufox was selected because:

1. **Firefox engine** — sidesteps the entire Chromium detection surface. The test kit explicitly checks for `$cdc_asdjflasutopfhvcZLmcfl_` (ChromeDriver marker), `chrome.runtime` patterns, and Puppeteer-specific artifacts. All of these checks pass cleanly on Firefox.
2. **Fingerprint rotation** — uses BrowserLeaks population data to generate realistic `navigator.hardwareConcurrency`, `deviceMemory`, WebGL renderer strings, canvas fingerprints, and audio fingerprints. Each session gets a unique, statistically plausible identity.
3. **Playwright API** — minimal code changes from our existing infrastructure. The async API (`AsyncCamoufox`) integrates cleanly with Celery's event loop.

### Camoufox Launch Configuration

```python
async with AsyncCamoufox(
    headless="virtual",
    humanize=True,
    block_webrtc=True,
    disable_coop=True,
    geoip=True,
) as browser:
```

Each parameter was selected through iterative testing:

| Parameter | Value | Why |
|---|---|---|
| `headless` | `"virtual"` | Uses Xvfb (virtual framebuffer) — runs a **headed** browser in a virtual display. `headless=True` uses Firefox's native headless mode, which has detectable differences in `navigator.plugins`, `window.outerHeight`, and rendering behavior. Virtual framebuffer is indistinguishable from a real display. |
| `humanize` | `True` | Adds micro-randomization to mouse movements, click timing, and scroll behavior. Passes behavioral scoring in kits that track input event patterns. |
| `block_webrtc` | `True` | Prevents WebRTC IP leakage that could expose the Docker container's internal network. Some kits use WebRTC to detect VPN/proxy usage. |
| `disable_coop` | `True` | **Critical breakthrough.** Disables Cross-Origin-Opener-Policy enforcement. See dedicated section below. |
| `geoip` | `True` | Randomizes the browser's geolocation to match the IP's geographic region. Prevents timezone/locale mismatches that fingerprinting systems flag. |

### The `disable_coop=True` Breakthrough

This was the single most important configuration change. Cross-Origin-Opener-Policy (COOP) is a browser security header that isolates the browsing context of a page from cross-origin popups and openers.

Cloudflare's Turnstile iframe sets `Cross-Origin-Opener-Policy: same-origin` on the challenge frame. When COOP is enforced, the parent page and the Turnstile iframe operate in isolated browsing contexts. This means:

1. The Turnstile JavaScript in the iframe cannot communicate its resolution state back to the parent page's JavaScript.
2. The parent page's `postMessage` listener never receives the success callback.
3. The second-stage decryption (which waits for Turnstile resolution) never triggers through the normal flow.

**However**, with `disable_coop=True`, the browsing context isolation is relaxed. The Turnstile iframe and the parent page share a browsing context. Even though Turnstile silently refused to render a checkbox (it fingerprinted the browser and decided not to present a challenge), the relaxed COOP allowed the page's JavaScript to proceed past the Turnstile gate.

The result: Camoufox captured the full 354KB rendered credential form — Stage 3 content — even without formally "solving" the Turnstile challenge.

**Evidence of Turnstile's silent failure**: Turnstile loaded (8 network requests to `challenges.cloudflare.com/cdn-cgi/challenge-platform/`), but `window.turnstile` remained `undefined` and the `cf-turnstile-response` input was never populated. Turnstile fingerprinted the browser, scored it as suspicious, and silently refused to render an interactive challenge. Under normal COOP enforcement, this would have blocked progression to Stage 3.

### Turnstile Click Handler (for Interactive Challenges)

Not all Turnstile deployments silently fail — some present an interactive checkbox. We implemented a click handler that works around a known Firefox/Playwright bug:

**The Problem**: Playwright's `frame_locator("iframe[src*='challenges.cloudflare.com']")` fails entirely on Firefox for cross-origin iframes. This is Playwright bug [#26317](https://github.com/microsoft/playwright/issues/26317). The frame locator returns a handle, but any interaction (`.click()`, `.locator()`) throws `Error: Frame was detached`.

**The Solution**: Iterate `page.frames` directly to find the Cloudflare challenge frame, get the iframe element via `frame.frame_element()`, extract its bounding box, and click via absolute page coordinates:

```python
for frame in page.frames:
    if "challenges.cloudflare.com" in frame.url:
        frame_element = await frame.frame_element()
        box = await frame_element.bounding_box()
        if box:
            # Checkbox sits at ~1/9th width from left, vertically centered
            click_x = box["x"] + box["width"] / 9
            click_y = box["y"] + box["height"] / 2
            await page.mouse.click(click_x, click_y)
```

The Turnstile checkbox is positioned at approximately 1/9th of the iframe width from the left edge, vertically centered. This coordinate targeting was determined by inspecting the Turnstile widget layout across multiple phishing pages.

**Fallback path**: If no cross-origin frame is found (some Turnstile deployments inline the widget), we click the `.cf-turnstile` wrapper div directly at `x + 25px, y + height/2`.

**Token polling**: After clicking, we poll for the response token (12 attempts, 1s interval):

```python
async def _turnstile_solved(page) -> bool:
    return await page.evaluate("""
        () => {
            const resp = document.querySelector('input[name="cf-turnstile-response"]');
            return !!(resp && resp.value && resp.value.length > 0);
        }
    """)
```

### Pre-Turnstile JS Execution Delay

Multi-stage kits need time to execute their first eval layer before the Turnstile script tag is even injected into the DOM. Without a delay, the Turnstile check runs before Stage 2 is decoded:

```python
# After page.goto(), before Turnstile check:
await asyncio.sleep(random.uniform(3.0, 5.0))
```

This 3-5s randomized delay allows:
- The PRNG cipher to decode Stage 2 HTML
- The decoded DOM to be written via `document.write()` or `innerHTML`
- The Turnstile `<script>` tag to be parsed and begin loading
- The `challenges.cloudflare.com` iframe to initialize

### Behavioral Simulation

Many phishing kits track mouse/keyboard events and score the interaction. We simulate minimal human behavior after Turnstile handling:

```python
async def _simulate_human_behavior(page) -> None:
    viewport = page.viewport_size or {"width": 1280, "height": 800}
    w, h = viewport["width"], viewport["height"]

    for _ in range(random.randint(3, 6)):
        x = random.randint(int(w * 0.1), int(w * 0.9))
        y = random.randint(int(h * 0.1), int(h * 0.7))
        await page.mouse.move(x, y)
        await asyncio.sleep(random.uniform(0.1, 0.4))

    await page.mouse.wheel(0, random.randint(50, 200))
    await asyncio.sleep(random.uniform(0.3, 0.8))
```

This passes simple behavioral checks but won't defeat deep behavioral scoring (10+ seconds of tracked movement patterns).

---

## Architecture: Two-Phase Routing

```
                     +-----------------------+
                     | worker-downloads      |
                     | (prefork -c 4)        |
    submit URL ----->| Queue: downloads      |
                     | httpx fast path (~1s)  |
                     +----------+------------+
                                |
                    CF challenge detected?
                     /                    \
                   No                     Yes
                   |                       |
            Continue chain         Dispatch to browser queue
            (steps 2-14)                   |
                                +----------v------------+
                                | worker-browser        |
                                | (solo pool)           |
                                | Queue: browser        |
                                | Camoufox (~10-15s)    |
                                +----------+------------+
                                           |
                                   Create child kit
                                   (parent→child link)
                                           |
                                   Continue chain
                                   (steps 2-14)
```

### Why Two Separate Workers

1. **Resource isolation**: Camoufox launches a full Firefox process (~300MB RAM). The prefork download worker runs 4 concurrent httpx connections at ~10MB each. Mixing them would cause OOM kills.
2. **Pool compatibility**: Camoufox is async/single-threaded. The download worker uses prefork for true parallelism. Solo pool (sequential processing) is required for browser work.
3. **Scale independently**: Scale browser workers for campaigns: `docker compose up --scale worker-browser=3`

### Cloudflare Challenge Detection

The download task detects Cloudflare challenges via:

```python
def is_cloudflare_challenge(reason: str, response_body: str | None = None) -> bool:
    if "ConnectError" in reason:     # TLS-level block
        return True
    if "HTTP 403" in reason:         # Cloudflare deny
        return True
    if response_body:                # Challenge page markers
        for marker in _CF_CHALLENGE_MARKERS:
            if marker in response_body:
                return True
    return False
```

Markers checked in response bodies:
- `challenges.cloudflare.com` — Turnstile script source
- `cf-turnstile` — Widget CSS class
- `cf_chl_opt` — Challenge options object
- `jschl_vc` — Legacy JS challenge variable
- `Just a moment` / `Checking your browser` / `Attention Required` — Interstitial page text

---

## Child Kit Linkage

When the browser worker succeeds, it creates a **new child kit record** rather than overwriting the parent:

| Field | Parent Kit (httpx) | Child Kit (browser) |
|---|---|---|
| `status` | `ANALYZED` | Goes through full analysis chain |
| `local_path` | Raw JS loader (Stage 1) | Rendered credential form (Stage 3) |
| `parent_kit_id` | `NULL` | Points to parent's UUID |
| `chain_depth` | `0` | `1` |
| `discovery_method` | `NULL` / feed source | `browser_render` |
| `investigation_id` | Shared | Shared |

Both artifacts are preserved as separate entities. The parent's JS loader content is valuable for YARA signature development (detecting the obfuscation pattern), while the child's rendered content is valuable for IOC extraction (C2 URLs, exfil endpoints, brand impersonation).

The investigation's `total_kits` counter is incremented and `total_depth_reached` is updated when the child kit is created. `finalize_kit` checks if all kits in the investigation are terminal (ANALYZED or FAILED) and marks the investigation COMPLETED.

---

## What This Won't Solve

1. **Deep behavioral analysis**: Kits that track mouse movement patterns for 10+ seconds with ML-based scoring. Our simulation is basic (3-6 random movements + scroll).
2. **Google reCAPTCHA v2/v3**: Would need a CAPTCHA solving service. Not common on phishing pages (Turnstile is free; reCAPTCHA requires a Google account).
3. **Device-bound sessions**: Kits requiring specific referrer chains or session cookies from the original phishing email link.
4. **Turnstile interactive mode with advanced fingerprinting**: If Turnstile presents an interactive challenge AND scores the browser fingerprint as suspicious, the click alone won't suffice — the challenge-platform backend rejects the response.
