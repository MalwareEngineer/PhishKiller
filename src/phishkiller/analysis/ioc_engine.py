"""IOC extraction engine for phishing kit source files."""

import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Guard rails for pathological files (the P99 file is ~50 KB; the outlier
# that took 7,794 seconds was a multi-MB minified HTML blob).
MAX_FILE_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB — skip files larger than this
MAX_SCAN_SECONDS = 120  # 2 minutes per file — abort and return partial IOCs
MAX_LINE_LENGTH = 100_000  # 100 KB — truncate longer lines before regex (minified JS/HTML)

from phishkiller.analysis.patterns import (
    BASE64_BLOCK_PATTERN,
    BENIGN_DOMAINS,
    BENIGN_URL_EXTENSIONS,
    BITCOIN_PATTERN,
    C2_KEYWORDS,
    C2_URL_PATTERN,
    DOMAIN_PATTERN,
    EMAIL_EXCLUSIONS,
    EMAIL_PATTERN,
    ETHEREUM_PATTERN,
    FALSE_DOMAIN_EXTENSIONS,
    IPV4_PATTERN,
    JS_FALSE_DOMAINS,
    _JS_OBJECT_PREFIXES,
    _JS_PRONE_TLDS,
    PHP_MAIL_PATTERN,
    PHP_MAIL_TO_PATTERN,
    PHONE_PATTERN,
    PRIVATE_IP_PREFIXES,
    SMTP_HOST_PATTERN,
    SMTP_PASS_PATTERN,
    SMTP_USER_PATTERN,
    TELEGRAM_API_PATTERN,
    TELEGRAM_BOT_TOKEN_PATTERN,
    TELEGRAM_CHAT_ID_PATTERN,
    TELEGRAM_HANDLE_EXCLUSIONS,
    TELEGRAM_HANDLE_PATTERN,
    URL_TRAILING_JUNK,
    VALID_TLDS,
    extract_root_domain,
    is_benign_url,
)
from phishkiller.models.indicator import IndicatorType

PROCESSABLE_EXTENSIONS = {
    ".php", ".js", ".html", ".htm", ".txt", ".json",
    ".conf", ".ini", ".xml", ".inc",
}


@dataclass
class ExtractedIOC:
    type: IndicatorType
    value: str
    source_file: str
    line_number: int
    context: str
    confidence: int


@dataclass
class ExtractionResult:
    iocs: list[ExtractedIOC] = field(default_factory=list)
    files_processed: int = 0
    errors: list[str] = field(default_factory=list)


class IOCExtractor:
    """Scans phishing kit files for indicators of compromise."""

    def scan_directory(self, directory: str) -> ExtractionResult:
        result = ExtractionResult()
        for root, _, files in os.walk(directory):
            for filename in files:
                filepath = os.path.join(root, filename)
                ext = Path(filepath).suffix.lower()
                if ext in PROCESSABLE_EXTENSIONS:
                    try:
                        file_iocs = self._scan_file(filepath, directory)
                        result.iocs.extend(file_iocs)
                        result.files_processed += 1
                    except Exception as e:
                        result.errors.append(f"{filepath}: {e}")
        result.iocs = self._deduplicate(result.iocs)
        return result

    def scan_content(
        self, content: str, source_file: str = "<string>"
    ) -> list[ExtractedIOC]:
        """Scan a string for IOCs (useful for testing or one-off analysis)."""
        iocs: list[ExtractedIOC] = []
        lines = content.split("\n")
        deadline = time.monotonic() + MAX_SCAN_SECONDS

        for line_num, line in enumerate(lines, start=1):
            # Check timeout every 500 lines
            if line_num % 500 == 0 and time.monotonic() > deadline:
                logger.warning(
                    "IOC extraction timed out after %ds on %s at line %d/%d, "
                    "returning %d partial IOCs",
                    MAX_SCAN_SECONDS, source_file, line_num, len(lines), len(iocs),
                )
                break

            # Truncate mega-lines (minified JS/HTML) to prevent catastrophic
            # regex backtracking on a single line that never hits the timeout
            if len(line) > MAX_LINE_LENGTH:
                logger.debug(
                    "Truncating %d-char line at %s:%d to %d chars",
                    len(line), source_file, line_num, MAX_LINE_LENGTH,
                )
                line = line[:MAX_LINE_LENGTH]

            iocs.extend(self._extract_emails(line, source_file, line_num))
            iocs.extend(self._extract_telegram_tokens(line, source_file, line_num))
            iocs.extend(self._extract_telegram_chat_ids(line, source_file, line_num))
            iocs.extend(self._extract_telegram_handles(line, source_file, line_num))

            # Extract URLs first, then pass their hostnames to domain extraction
            # so we don't double-count domains already captured in URLs
            url_iocs = self._extract_urls(line, source_file, line_num)
            iocs.extend(url_iocs)
            url_hostnames = set()
            for ioc in url_iocs:
                try:
                    hostname = urlparse(ioc.value).hostname
                    if hostname:
                        url_hostnames.add(hostname.lower())
                except Exception:
                    pass

            iocs.extend(self._extract_domains(
                line, source_file, line_num, skip_domains=url_hostnames,
            ))
            iocs.extend(self._extract_ips(line, source_file, line_num))
            iocs.extend(self._extract_smtp_creds(line, source_file, line_num))
            iocs.extend(self._extract_crypto_wallets(line, source_file, line_num))
            iocs.extend(self._extract_phone_numbers(line, source_file, line_num))

        iocs.extend(self._extract_base64_blocks(content, source_file))
        return self._deduplicate(iocs)

    def scan_file(self, filepath: str) -> ExtractionResult:
        """Scan a single file for IOCs. Returns an ExtractionResult."""
        result = ExtractionResult()
        try:
            file_iocs = self._scan_file(filepath, str(Path(filepath).parent))
            result.iocs.extend(file_iocs)
            result.files_processed = 1
        except Exception as e:
            result.errors.append(f"{filepath}: {e}")
        result.iocs = self._deduplicate(result.iocs)
        return result

    def _scan_file(self, filepath: str, base_dir: str) -> list[ExtractedIOC]:
        relative_path = os.path.relpath(filepath, base_dir)

        # Skip oversized files — they cause multi-hour regex stalls
        try:
            file_size = os.path.getsize(filepath)
        except OSError:
            return []
        if file_size > MAX_FILE_SIZE_BYTES:
            logger.warning(
                "Skipping IOC extraction for %s (%d bytes > %d byte limit)",
                relative_path, file_size, MAX_FILE_SIZE_BYTES,
            )
            return []

        try:
            with open(filepath, encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except Exception:
            return []

        return self.scan_content(content, relative_path)

    def _extract_emails(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []

        # High-confidence: PHP mail() targets
        for pattern in (PHP_MAIL_PATTERN, PHP_MAIL_TO_PATTERN):
            for match in pattern.finditer(line):
                email = match.group(1)
                domain = email.split("@")[1].lower()
                if domain not in EMAIL_EXCLUSIONS and extract_root_domain(domain) not in BENIGN_DOMAINS:
                    results.append(ExtractedIOC(
                        type=IndicatorType.EMAIL,
                        value=email,
                        source_file=source_file,
                        line_number=line_num,
                        context=line[:200],
                        confidence=90,
                    ))

        # Standard email extraction
        for match in EMAIL_PATTERN.finditer(line):
            email = match.group(0)
            domain = email.split("@")[1].lower()
            if domain in EMAIL_EXCLUSIONS:
                continue
            # Also check root domain (catches uuid@o293668.ingest.sentry.io etc.)
            root = extract_root_domain(domain)
            if root in BENIGN_DOMAINS:
                continue
            # Skip if already captured by mail() patterns
            if any(ioc.value == email for ioc in results):
                continue
            confidence = 70
            if any(
                kw in line.lower()
                for kw in ("send", "mail(", "smtp", "result", "$to")
            ):
                confidence = 85
            results.append(ExtractedIOC(
                type=IndicatorType.EMAIL,
                value=email,
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=confidence,
            ))
        return results

    def _extract_telegram_tokens(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []
        for match in TELEGRAM_BOT_TOKEN_PATTERN.finditer(line):
            results.append(ExtractedIOC(
                type=IndicatorType.TELEGRAM_BOT_TOKEN,
                value=match.group(0),
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=95,
            ))
        return results

    def _extract_telegram_chat_ids(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []
        for match in TELEGRAM_CHAT_ID_PATTERN.finditer(line):
            results.append(ExtractedIOC(
                type=IndicatorType.TELEGRAM_CHAT_ID,
                value=match.group(1),
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=85,
            ))
        return results

    def _extract_urls(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []

        # Telegram API URLs (high confidence)
        telegram_urls = set()
        for match in TELEGRAM_API_PATTERN.finditer(line):
            url = URL_TRAILING_JUNK.sub("", match.group(0))
            telegram_urls.add(url)
            results.append(ExtractedIOC(
                type=IndicatorType.C2_URL,
                value=url,
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=95,
            ))

        # General C2/exfil URLs
        for match in C2_URL_PATTERN.finditer(line):
            url = match.group(0)

            # Strip trailing syntax junk (quotes, semicolons, commas, etc.)
            url = URL_TRAILING_JUNK.sub("", url)

            url_lower = url.lower()

            # Skip if already captured as Telegram API URL
            if url in telegram_urls:
                continue
            if "api.telegram.org" in url_lower:
                continue

            # Skip benign domains using root-domain matching
            if is_benign_url(url):
                continue

            # Skip javascript: pseudo-protocol URLs (https://javascript:...)
            try:
                parsed = urlparse(url)
                if parsed.hostname and parsed.hostname.lower() == "javascript":
                    continue
                url_path = parsed.path.lower()
            except Exception:
                url_path = url_lower

            # Skip URLs with base64 blobs as the hostname/path
            # (e.g. https://www.YXNkYXNkQGdtYWlsLmNvbQ==)
            if "==" in url_lower or "==" in (parsed.hostname or ""):
                continue

            # Skip static asset URLs — check the URL *path*, not the full string
            # so query strings like .js?ver=3.0 are still caught
            if any(url_path.endswith(ext) for ext in BENIGN_URL_EXTENSIONS):
                continue

            # Score confidence based on context
            confidence = 60
            line_lower = line.lower()
            if any(kw in url_lower or kw in line_lower for kw in C2_KEYWORDS):
                confidence = 85

            results.append(ExtractedIOC(
                type=IndicatorType.C2_URL,
                value=url,
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=confidence,
            ))
        return results

    def _extract_ips(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []
        for match in IPV4_PATTERN.finditer(line):
            ip = match.group(0)
            if any(ip.startswith(prefix) for prefix in PRIVATE_IP_PREFIXES):
                continue
            # Also skip 172.16-31.x.x
            parts = ip.split(".")
            if parts[0] == "172" and 16 <= int(parts[1]) <= 31:
                continue
            results.append(ExtractedIOC(
                type=IndicatorType.IP_ADDRESS,
                value=ip,
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=60,
            ))
        return results

    def _extract_smtp_creds(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []
        for pattern, label in [
            (SMTP_HOST_PATTERN, "host"),
            (SMTP_USER_PATTERN, "user"),
            (SMTP_PASS_PATTERN, "pass"),
        ]:
            for match in pattern.finditer(line):
                results.append(ExtractedIOC(
                    type=IndicatorType.SMTP_CREDENTIAL,
                    value=f"smtp_{label}={match.group(1)}",
                    source_file=source_file,
                    line_number=line_num,
                    context=line[:200],
                    confidence=85,
                ))
        return results

    def _extract_crypto_wallets(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []
        for match in BITCOIN_PATTERN.finditer(line):
            results.append(ExtractedIOC(
                type=IndicatorType.CRYPTOCURRENCY_WALLET,
                value=match.group(0),
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=70,
            ))
        for match in ETHEREUM_PATTERN.finditer(line):
            results.append(ExtractedIOC(
                type=IndicatorType.CRYPTOCURRENCY_WALLET,
                value=match.group(0),
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=70,
            ))
        return results

    def _extract_domains(
        self, line: str, source_file: str, line_num: int,
        skip_domains: set[str] | None = None,
    ) -> list[ExtractedIOC]:
        results = []
        skip = skip_domains or set()

        for match in DOMAIN_PATTERN.finditer(line):
            domain = match.group(1).lower()

            # Skip domains already captured as part of URLs
            if domain in skip:
                continue

            # Skip URL-encoded fragments (e.g. "2fwww.ionos.com" from %2F...)
            if domain[:2] in ("2f", "3a", "3d", "26", "3f"):
                continue
            # Also catch hex-encoded prefixes like "https3a2f2f..."
            if any(frag in domain for frag in ("3a2f", "2f2f")):
                continue

            # Use root-domain matching for benign check
            root = extract_root_domain(domain)
            if root in BENIGN_DOMAINS:
                continue
            if domain in JS_FALSE_DOMAINS:
                continue

            # Skip JS object property access patterns (this.br, caller.name, etc.)
            if any(domain.startswith(prefix) for prefix in _JS_OBJECT_PREFIXES):
                continue

            # Skip very short domains (likely false positives)
            if len(domain) < 5:
                continue
            # Must have at least one dot (SLD.TLD)
            if "." not in domain:
                continue
            tld = domain.rsplit(".", 1)[-1]
            # Skip if the "TLD" is actually a file extension
            if "." + tld in FALSE_DOMAIN_EXTENSIONS:
                continue
            # Only accept real TLDs
            if tld not in VALID_TLDS:
                continue
            # Require each label to be 2+ chars (filters w.com, a.net)
            labels = domain.split(".")
            if any(len(label) < 2 for label in labels):
                continue

            # Skip CSS class-like patterns that end in a valid TLD (e.g.
            # "wp-block-buttons.is", "spectrum-textfield--multiline.is")
            # Real domains rarely have double-hyphens or BEM-like naming
            if "--" in domain or (
                tld == "is" and "-" in labels[0] and len(labels) == 2
            ):
                continue

            # Skip JS-prone TLDs when the SLD looks like a variable name
            # (single label, no hyphens, not a known registrar pattern)
            if tld in _JS_PRONE_TLDS and len(labels) == 2:
                sld = labels[0]
                # Real domains usually aren't camelCase or pure lowercase
                # JS vars like "rootdiv", "errgroupobj", "functioncaller"
                if any(c.isupper() for c in sld[1:]):  # camelCase
                    continue
                # Very long single-word SLD + JS-prone TLD = likely JS var
                if len(sld) > 12 and "-" not in sld:
                    continue

            confidence = 60
            line_lower = line.lower()
            if any(
                kw in line_lower
                for kw in ("host", "server", "smtp", "url", "send", "post", "gate")
            ):
                confidence = 80
            results.append(ExtractedIOC(
                type=IndicatorType.DOMAIN,
                value=domain,
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=confidence,
            ))
        return results

    def _extract_phone_numbers(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []
        for match in PHONE_PATTERN.finditer(line):
            phone = match.group(0).strip()
            results.append(ExtractedIOC(
                type=IndicatorType.PHONE_NUMBER,
                value=phone,
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=65,
            ))
        return results

    def _extract_telegram_handles(
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []
        for match in TELEGRAM_HANDLE_PATTERN.finditer(line):
            handle = match.group(1).lower()
            if handle in TELEGRAM_HANDLE_EXCLUSIONS:
                continue
            # Skip if it looks like a CSS/JS keyword (all lowercase, common word)
            if len(handle) < 5:
                continue
            results.append(ExtractedIOC(
                type=IndicatorType.TELEGRAM_CHAT_ID,  # Re-use existing type for handles
                value=f"@{handle}",
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=70,
            ))
        return results

    def _extract_base64_blocks(
        self, content: str, source_file: str
    ) -> list[ExtractedIOC]:
        results = []
        for match in BASE64_BLOCK_PATTERN.finditer(content):
            block = match.group(0)
            if len(block) >= 100:
                results.append(ExtractedIOC(
                    type=IndicatorType.BASE64_BLOCK,
                    value=block[:500],
                    source_file=source_file,
                    line_number=0,
                    context=f"Base64 block, {len(block)} chars",
                    confidence=40,
                ))
        return results

    def _deduplicate(self, iocs: list[ExtractedIOC]) -> list[ExtractedIOC]:
        seen: dict[tuple, ExtractedIOC] = {}
        for ioc in iocs:
            key = (ioc.type, ioc.value)
            if key not in seen or ioc.confidence > seen[key].confidence:
                seen[key] = ioc
        return list(seen.values())
