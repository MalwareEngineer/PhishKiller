"""EML (email message) parser — extracts headers, body, links, attachments."""

import email
import email.policy
import logging
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path

logger = logging.getLogger(__name__)

# Image MIME types we care about (for QR code scanning downstream)
IMAGE_TYPES = frozenset({
    "image/png", "image/jpeg", "image/gif", "image/bmp", "image/webp",
})


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    data: bytes
    size: int


@dataclass
class EmbeddedImage:
    content_id: str | None
    content_type: str
    data: bytes
    filename: str | None


@dataclass
class EMLParseResult:
    headers: dict[str, str] = field(default_factory=dict)
    body_text: str | None = None
    body_html: str | None = None
    links: list[str] = field(default_factory=list)
    attachments: list[AttachmentInfo] = field(default_factory=list)
    embedded_images: list[EmbeddedImage] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


class _LinkExtractor(HTMLParser):
    """Extract URLs from href, src, and form action attributes."""

    def __init__(self):
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        attr_dict = dict(attrs)
        url = None
        if tag == "a":
            url = attr_dict.get("href")
        elif tag in ("img", "script", "iframe", "embed", "source", "video", "audio"):
            url = attr_dict.get("src")
        elif tag == "form":
            url = attr_dict.get("action")
        elif tag == "link":
            url = attr_dict.get("href")
        elif tag == "meta":
            # Handle meta refresh redirects
            content = attr_dict.get("content", "")
            if attr_dict.get("http-equiv", "").lower() == "refresh" and "url=" in content.lower():
                match = re.search(r"url\s*=\s*['\"]?([^'\";\s]+)", content, re.IGNORECASE)
                if match:
                    url = match.group(1)

        if url and url.startswith(("http://", "https://")):
            self.links.append(url)

    def error(self, message: str):
        pass  # Suppress HTMLParser errors


# Regex fallback for URLs in plain text
_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def _walk_skip_rfc822(msg):
    """Like msg.walk() but does not descend into message/rfc822 parts.

    We handle message/rfc822 via explicit recursion in parse_bytes(),
    so the default walk() would double-process inner parts.
    """
    yield msg
    # If this part IS message/rfc822, don't descend — children are
    # handled by recursive parse_bytes() call in the walk loop.
    if msg.get_content_type() == "message/rfc822":
        return
    if msg.is_multipart():
        for part in msg.get_payload():
            yield from _walk_skip_rfc822(part)


class EMLParser:
    """Parse .eml files to extract headers, body, links, attachments, and images."""

    def parse(self, filepath: str) -> EMLParseResult:
        """Parse an .eml file from disk."""
        try:
            with open(filepath, "rb") as f:
                return self.parse_bytes(f.read())
        except Exception as e:
            logger.exception("Failed to read EML file %s: %s", filepath, e)
            return EMLParseResult(errors=[f"read_error: {e}"])

    def parse_bytes(self, raw: bytes) -> EMLParseResult:
        """Parse raw email bytes."""
        result = EMLParseResult()
        try:
            msg = email.message_from_bytes(raw, policy=email.policy.default)
        except Exception as e:
            result.errors.append(f"parse_error: {e}")
            return result

        # Extract headers
        for key in ("From", "To", "Subject", "Date", "Message-ID",
                     "Reply-To", "Return-Path", "X-Mailer", "X-Originating-IP",
                     "Received", "Content-Type", "DKIM-Signature"):
            val = msg.get(key)
            if val:
                result.headers[key] = str(val)

        # Extract all Received headers (can be multiple)
        received = msg.get_all("Received")
        if received:
            result.headers["Received-All"] = "\n".join(str(r) for r in received)

        # Walk MIME parts (skip into message/rfc822 — handled via recursion)
        for part in _walk_skip_rfc822(msg):
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            # Nested EML (message/rfc822) — recurse into inner message
            if content_type == "message/rfc822":
                inner_payloads = part.get_payload()
                if isinstance(inner_payloads, list):
                    for inner_msg in inner_payloads:
                        try:
                            inner_bytes = inner_msg.as_bytes()
                            inner_result = self.parse_bytes(inner_bytes)
                            result.attachments.extend(inner_result.attachments)
                            result.embedded_images.extend(inner_result.embedded_images)
                            result.links.extend(inner_result.links)
                            if not result.body_html and inner_result.body_html:
                                result.body_html = inner_result.body_html
                            if not result.body_text and inner_result.body_text:
                                result.body_text = inner_result.body_text
                            result.errors.extend(inner_result.errors)
                            # Save inner EML as attachment
                            fname = part.get_filename()
                            if not fname:
                                subj = inner_msg.get("Subject", "inner")
                                fname = str(subj).replace("/", "_")[:80] + ".eml"
                            result.attachments.append(AttachmentInfo(
                                filename=fname,
                                content_type="message/rfc822",
                                data=inner_bytes,
                                size=len(inner_bytes),
                            ))
                        except Exception as e:
                            result.errors.append(f"inner_eml_error: {e}")
                continue

            # Embedded images (inline with Content-ID)
            if content_type in IMAGE_TYPES:
                try:
                    data = part.get_payload(decode=True)
                    if data:
                        result.embedded_images.append(EmbeddedImage(
                            content_id=part.get("Content-ID"),
                            content_type=content_type,
                            data=data,
                            filename=part.get_filename(),
                        ))
                except Exception as e:
                    result.errors.append(f"image_decode_error: {e}")
                continue

            # Attachments (non-text parts with filenames or explicit attachment disposition)
            if "attachment" in disposition or (
                part.get_filename() and content_type not in ("text/plain", "text/html")
            ):
                try:
                    data = part.get_payload(decode=True)
                    if data:
                        fname = part.get_filename() or "attachment"
                        result.attachments.append(AttachmentInfo(
                            filename=fname,
                            content_type=content_type,
                            data=data,
                            size=len(data),
                        ))
                except Exception as e:
                    result.errors.append(f"attachment_decode_error: {e}")
                continue

            # Text bodies
            if content_type == "text/plain" and not result.body_text:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        result.body_text = payload.decode("utf-8", errors="replace")
                except Exception as e:
                    result.errors.append(f"text_decode_error: {e}")

            elif content_type == "text/html" and not result.body_html:
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        result.body_html = payload.decode("utf-8", errors="replace")
                except Exception as e:
                    result.errors.append(f"html_decode_error: {e}")

        # Extract links from HTML body
        if result.body_html:
            result.links.extend(self._extract_links_from_html(result.body_html))

        # Extract links from plain text body
        if result.body_text:
            result.links.extend(self._extract_links_from_text(result.body_text))

        # Deduplicate links preserving order
        seen = set()
        deduped = []
        for link in result.links:
            if link not in seen:
                seen.add(link)
                deduped.append(link)
        result.links = deduped

        return result

    def _extract_links_from_html(self, html: str) -> list[str]:
        """Extract URLs from HTML using HTMLParser."""
        extractor = _LinkExtractor()
        try:
            extractor.feed(html)
        except Exception as e:
            logger.debug("HTML link extraction error: %s", e)
        return extractor.links

    def _extract_links_from_text(self, text: str) -> list[str]:
        """Extract URLs from plain text using regex."""
        return _URL_RE.findall(text)

    def save_attachments(self, result: EMLParseResult, output_dir: str) -> list[str]:
        """Save attachments and embedded images to disk. Returns saved file paths."""
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        saved = []

        for att in result.attachments:
            dest = out / att.filename
            # Prevent path traversal
            if not dest.resolve().is_relative_to(out.resolve()):
                continue
            dest.write_bytes(att.data)
            saved.append(str(dest))

        for i, img in enumerate(result.embedded_images):
            ext = img.content_type.split("/")[-1] if "/" in img.content_type else "bin"
            fname = img.filename or f"embedded_{i}.{ext}"
            dest = out / fname
            if not dest.resolve().is_relative_to(out.resolve()):
                continue
            dest.write_bytes(img.data)
            saved.append(str(dest))

        # Save HTML body to disk for downstream YARA/IOC/deobfuscation
        if result.body_html:
            html_dest = out / "body.html"
            html_dest.write_text(result.body_html, encoding="utf-8")
            saved.append(str(html_dest))

        return saved
