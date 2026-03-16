"""QR code detection and URL extraction from images."""

import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

IMAGE_EXTENSIONS = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp",
})


@dataclass
class QRDecodeResult:
    urls: list[str] = field(default_factory=list)
    qr_count: int = 0
    errors: list[str] = field(default_factory=list)


class QRDecoder:
    """Scan images for QR codes and extract URLs."""

    def __init__(self):
        try:
            from PIL import Image  # noqa: F401
            from pyzbar import pyzbar  # noqa: F401
            self._available = True
        except ImportError:
            self._available = False
            logger.warning("pyzbar or Pillow not installed; QR decoding disabled")

    def decode_file(self, filepath: str) -> QRDecodeResult:
        """Decode QR codes from a single image file."""
        if not self._available:
            return QRDecodeResult()

        result = QRDecodeResult()
        try:
            self._scan_image(filepath, result)
        except Exception as e:
            result.errors.append(f"{filepath}: {e}")
        return result

    def decode_bytes(self, data: bytes) -> QRDecodeResult:
        """Decode QR codes from raw image bytes."""
        if not self._available:
            return QRDecodeResult()

        result = QRDecodeResult()
        try:
            import io

            from PIL import Image
            from pyzbar import pyzbar

            img = Image.open(io.BytesIO(data))
            decoded = pyzbar.decode(img)
            for obj in decoded:
                result.qr_count += 1
                text = obj.data.decode("utf-8", errors="replace")
                if self._is_url(text):
                    result.urls.append(text)
        except Exception as e:
            result.errors.append(f"bytes: {e}")
        return result

    def scan_directory(self, directory: str) -> QRDecodeResult:
        """Scan all images in a directory tree for QR codes."""
        if not self._available:
            return QRDecodeResult()

        result = QRDecodeResult()
        dir_path = Path(directory)

        if not dir_path.is_dir():
            result.errors.append(f"not_a_directory: {directory}")
            return result

        for filepath in dir_path.rglob("*"):
            if filepath.suffix.lower() not in IMAGE_EXTENSIONS:
                continue
            if filepath.stat().st_size > 20 * 1024 * 1024:  # Skip files > 20MB
                continue
            try:
                self._scan_image(str(filepath), result)
            except Exception as e:
                result.errors.append(f"{filepath.name}: {e}")

        # Deduplicate URLs
        result.urls = list(dict.fromkeys(result.urls))
        return result

    def _scan_image(self, filepath: str, result: QRDecodeResult):
        """Scan a single image file for QR codes."""
        from PIL import Image
        from pyzbar import pyzbar

        img = Image.open(filepath)
        decoded = pyzbar.decode(img)

        for obj in decoded:
            result.qr_count += 1
            text = obj.data.decode("utf-8", errors="replace")
            if self._is_url(text):
                result.urls.append(text)

    @staticmethod
    def _is_url(text: str) -> bool:
        """Check if decoded QR data looks like a URL."""
        return text.startswith(("http://", "https://"))
