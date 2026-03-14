"""IOC extraction engine for phishing kit source files."""

import os
from dataclasses import dataclass, field
from pathlib import Path

from phishkiller.analysis.patterns import (
    BASE64_BLOCK_PATTERN,
    BENIGN_DOMAINS,
    BENIGN_URL_DOMAINS,
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
    VALID_TLDS,
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

        for line_num, line in enumerate(lines, start=1):
            iocs.extend(self._extract_emails(line, source_file, line_num))
            iocs.extend(self._extract_telegram_tokens(line, source_file, line_num))
            iocs.extend(self._extract_telegram_chat_ids(line, source_file, line_num))
            iocs.extend(self._extract_telegram_handles(line, source_file, line_num))
            iocs.extend(self._extract_urls(line, source_file, line_num))
            iocs.extend(self._extract_domains(line, source_file, line_num))
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
                if domain not in EMAIL_EXCLUSIONS:
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
        for match in TELEGRAM_API_PATTERN.finditer(line):
            results.append(ExtractedIOC(
                type=IndicatorType.C2_URL,
                value=match.group(0),
                source_file=source_file,
                line_number=line_num,
                context=line[:200],
                confidence=95,
            ))

        # General C2/exfil URLs
        for match in C2_URL_PATTERN.finditer(line):
            url = match.group(0)
            url_lower = url.lower()

            # Skip benign domains
            if any(benign in url_lower for benign in BENIGN_URL_DOMAINS):
                continue
            if "api.telegram.org" in url_lower:
                continue

            # Skip static asset URLs (CSS, fonts, images)
            if any(url_lower.endswith(ext) for ext in BENIGN_URL_EXTENSIONS):
                continue

            # Score confidence based on context
            confidence = 60  # base (raised from 50)
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
        self, line: str, source_file: str, line_num: int
    ) -> list[ExtractedIOC]:
        results = []
        for match in DOMAIN_PATTERN.finditer(line):
            domain = match.group(1).lower()
            if domain in BENIGN_DOMAINS:
                continue
            if domain in JS_FALSE_DOMAINS:
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
            # Only accept real TLDs — kills JS property false positives
            # like w.length, document.fonts, date.now, window.google
            if tld not in VALID_TLDS:
                continue
            # Require each label to be 2+ chars (filters w.com, a.net)
            labels = domain.split(".")
            if any(len(label) < 2 for label in labels):
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
