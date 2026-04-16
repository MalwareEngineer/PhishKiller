"""Detect and decrypt AES-GCM encrypted HTML phishing payloads.

Some phishing kits embed the entire phishing page as an AES-GCM encrypted
blob in a <script> tag, decrypted client-side via crypto.subtle.decrypt().
The key, IV, and ciphertext are all inline as base64 strings — we can
decrypt server-side without a JS engine.
"""

import base64
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

# Max file size to attempt decryption on (10 MB — encrypted pages are typically <1 MB)
MAX_DECRYPT_SIZE = 10 * 1024 * 1024

# Pattern: three base64 variables assigned in sequence, followed by AES-GCM usage.
# Captures: ciphertext (long), IV (short), key (medium-length).
# Flexible on variable names and whitespace.
_B64 = r'"([A-Za-z0-9+/=]{10,})"'
_AES_GCM_VARS = re.compile(
    r'var\s+\w+\s*=\s*' + _B64 +
    r'\s*,\s*\w+\s*=\s*' + _B64 +
    r'\s*,\s*\w+\s*=\s*' + _B64,
    re.DOTALL,
)
_AES_GCM_MARKER = re.compile(r'crypto\.subtle\.(?:importKey|decrypt)', re.IGNORECASE)
_AES_GCM_ALGO = re.compile(r'AES-GCM', re.IGNORECASE)


@dataclass
class DecryptionResult:
    original_file: str
    decrypted_content: str | None = None
    decrypted_file: str | None = None
    encryption_type: str | None = None
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.decrypted_content is not None


class HTMLDecryptor:
    """Detect and decrypt AES-GCM encrypted HTML phishing pages."""

    def detect_and_decrypt(self, filepath: str) -> DecryptionResult:
        """Read an HTML file, detect AES-GCM pattern, decrypt if found."""
        path = Path(filepath)
        result = DecryptionResult(original_file=filepath)

        try:
            if path.stat().st_size > MAX_DECRYPT_SIZE:
                return result  # Too large, skip silently

            raw = path.read_bytes()
            content = self._decode_content(raw)
        except Exception as e:
            result.error = f"Failed to read {filepath}: {e}"
            logger.debug(result.error)
            return result

        # Quick gate: must have crypto.subtle and AES-GCM references
        if not _AES_GCM_MARKER.search(content) or not _AES_GCM_ALGO.search(content):
            return result  # Not encrypted, pass through

        # Extract the three base64 variables
        match = _AES_GCM_VARS.search(content)
        if not match:
            return result

        b64_1, b64_2, b64_3 = match.group(1), match.group(2), match.group(3)

        # Identify which is ciphertext (longest), IV (shortest), key (middle).
        parts = sorted(
            [(len(b64_1), b64_1), (len(b64_2), b64_2), (len(b64_3), b64_3)],
            key=lambda x: x[0],
        )
        iv_b64 = parts[0][1]   # shortest
        key_b64 = parts[1][1]  # middle
        ct_b64 = parts[2][1]   # longest

        try:
            decrypted = self._decrypt_aes_gcm(ct_b64, iv_b64, key_b64)
        except Exception as e:
            result.error = f"AES-GCM decryption failed: {e}"
            logger.warning("AES-GCM decryption failed for %s: %s", filepath, e)
            return result

        # Validate: decrypted content should look like HTML
        stripped = decrypted.strip()
        if not stripped:
            result.error = "Decrypted content is empty"
            return result

        html_indicators = ("<html", "<div", "<script", "<head", "<body", "<form", "<!doctype")
        if not any(indicator in stripped[:500].lower() for indicator in html_indicators):
            result.error = "Decrypted content does not look like HTML"
            logger.debug("Decrypted content from %s doesn't look like HTML, discarding", filepath)
            return result

        # Write decrypted file
        decrypted_path = Path(filepath + ".decrypted.html")
        decrypted_path.write_text(decrypted, encoding="utf-8")

        result.decrypted_content = decrypted
        result.decrypted_file = str(decrypted_path)
        result.encryption_type = "aes-gcm"

        logger.info(
            "Decrypted AES-GCM payload in %s → %s (%d bytes)",
            filepath, decrypted_path.name, len(decrypted),
        )
        return result

    @staticmethod
    def _decode_content(raw: bytes) -> str:
        """Decode file content, attempting Brotli/gzip decompression if needed.

        Some downloads are saved with Content-Encoding still applied (e.g. Brotli
        from Cloudflare Workers). Try strict UTF-8 first; if that fails, attempt
        decompression before falling back to lossy decode.
        """
        # Strict decode first — if it works, the file is plain text
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            pass

        # Binary data — try Brotli decompression (common from Cloudflare)
        try:
            import brotli

            return brotli.decompress(raw).decode("utf-8", errors="ignore")
        except Exception:
            pass

        # Try gzip
        try:
            import gzip

            return gzip.decompress(raw).decode("utf-8", errors="ignore")
        except Exception:
            pass

        # Last resort: lossy decode of the raw bytes
        return raw.decode("utf-8", errors="ignore")

    @staticmethod
    def _decrypt_aes_gcm(ciphertext_b64: str, iv_b64: str, key_b64: str) -> str:
        """Decrypt AES-GCM payload from base64 components."""
        ciphertext = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)
        key = base64.b64decode(key_b64)

        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(iv, ciphertext, None)
        return plaintext.decode("utf-8", errors="replace")
