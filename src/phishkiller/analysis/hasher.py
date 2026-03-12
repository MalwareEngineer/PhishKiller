"""File hashing — SHA256, MD5, SHA1, and TLSH (optional)."""

import hashlib
from dataclasses import dataclass
from pathlib import Path


@dataclass
class HashResult:
    sha256: str
    md5: str
    sha1: str
    tlsh: str | None
    file_size: int


def compute_hashes(filepath: str | Path, tlsh_min_size: int = 50) -> HashResult:
    """Compute all hashes for a file.

    TLSH requires a minimum of 50 bytes of data and is optional
    (the py-tlsh package requires C compilation).
    """
    filepath = Path(filepath)
    data = filepath.read_bytes()
    file_size = len(data)

    sha256 = hashlib.sha256(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()

    tlsh_hash = None
    if file_size >= tlsh_min_size:
        try:
            import tlsh

            tlsh_hash = tlsh.hash(data)
            if tlsh_hash == "TNULL" or tlsh_hash == "":
                tlsh_hash = None
        except ImportError:
            pass
        except Exception:
            pass

    return HashResult(
        sha256=sha256,
        md5=md5,
        sha1=sha1,
        tlsh=tlsh_hash,
        file_size=file_size,
    )


def compute_tlsh_distance(hash1: str, hash2: str) -> int | None:
    """Compute the TLSH distance between two hashes. Returns None if TLSH is unavailable."""
    try:
        import tlsh

        return tlsh.diff(hash1, hash2)
    except ImportError:
        return None
