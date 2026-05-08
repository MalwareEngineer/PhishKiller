"""Ad-hoc YARA compilation and scanning for the in-app rule playground.

Sibling of ``yara_scanner.py``.  That module loads & caches the production
rule bundle per worker process; this one accepts user-supplied rule source,
compiles it in isolation, and scans either stored kit files or arbitrary
bytes.  Kept separate so user rules cannot pollute the production cache
and so we can surface granular per-rule compile errors to the editor.

Sandboxing:
- Rejects ``include`` directives (no filesystem traversal via includes).
- Per-scan wall-clock timeout enforced via ``yara``'s ``timeout=`` arg
  *and* a subprocess kill at the API layer.
- Caller is responsible for capping target bytes / file counts.
"""

from __future__ import annotations

import logging
import mimetypes
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


# Conservative scannable-extension set.  Superset of yara_scanner's prod set
# because the playground is for analyst exploration — let them point YARA at
# anything plausibly text or commonly hidden in kits (mailers, eml, svg).
PLAYGROUND_SCANNABLE_EXTENSIONS: frozenset[str] = frozenset({
    ".php", ".js", ".html", ".htm", ".txt", ".json", ".conf", ".ini",
    ".xml", ".inc", ".htaccess", ".css", ".eml", ".svg", ".yar", ".yara",
    ".py", ".sh", ".bat", ".ps1", ".vbs", ".yml", ".yaml", ".cfg",
    ".asp", ".aspx", ".jsp", ".pl",
})

# Hard server-side ceilings — GUI-adjustable values are clamped to these.
MAX_FILES_CEILING = 5000
MAX_FILE_SIZE_MB_CEILING = 100
TIMEOUT_SECONDS_CEILING = 60

# Reject ``include`` directives at compile time — playground rules must be
# self-contained, can't pull arbitrary files off the API host's disk.
# Match the YARA grammar: ``include "path"`` (whitespace tolerant,
# line-anchored to avoid false positives inside string literals).
#
# NOTE: This deliberately does NOT match ``import`` — module imports
# (``import "pe"``, ``import "dotnet"``, ``import "math"``, ``import "hash"``,
# etc.) are first-class YARA features compiled into yara-python and pose no
# filesystem-traversal risk.  Analysts need them for any non-trivial rule.
_INCLUDE_RE = re.compile(r'^\s*include\s+"', re.MULTILINE)


@dataclass
class CompileError:
    line: int | None
    column: int | None
    message: str


@dataclass
class CompileResult:
    ok: bool
    rules_count: int = 0
    errors: list[CompileError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


@dataclass
class StringMatch:
    identifier: str
    offset: int
    matched: str
    context_before: str = ""
    context_after: str = ""


@dataclass
class Match:
    rule: str
    namespace: str
    tags: list[str]
    meta: dict
    target_kit_id: str | None
    target_path: str
    target_size: int
    target_mime: str | None
    strings: list[StringMatch]


@dataclass
class TargetError:
    target: str
    error: str


@dataclass
class ScanResult:
    matches: list[Match] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    duration_ms: int = 0
    target_errors: list[TargetError] = field(default_factory=list)


@dataclass
class ScanOpts:
    timeout_seconds: int = 10
    max_files: int = 500
    max_file_size_mb: int = 10
    include_strings: bool = True
    string_context_bytes: int = 64
    extensions: frozenset[str] | None = None  # None = use default playground set

    def clamp(self) -> ScanOpts:
        """Return a copy clamped to server ceilings."""
        return ScanOpts(
            timeout_seconds=max(1, min(self.timeout_seconds, TIMEOUT_SECONDS_CEILING)),
            max_files=max(1, min(self.max_files, MAX_FILES_CEILING)),
            max_file_size_mb=max(1, min(self.max_file_size_mb, MAX_FILE_SIZE_MB_CEILING)),
            include_strings=self.include_strings,
            string_context_bytes=max(0, min(self.string_context_bytes, 256)),
            extensions=self.extensions,
        )


class YaraUnavailableError(RuntimeError):
    """Raised when yara-python isn't installed."""


def is_yara_available() -> bool:
    try:
        import yara  # noqa: F401
        return True
    except ImportError:
        return False


def compile_source(source: str) -> tuple[CompileResult, object | None]:
    """Compile a YARA rule source string.

    Returns (result, compiled_rules_or_None).  Never raises on YARA errors
    — surfaces them through ``CompileResult.errors``.
    """
    if not is_yara_available():
        raise YaraUnavailableError("yara-python is not installed")

    if not source or not source.strip():
        return CompileResult(ok=False, errors=[CompileError(None, None, "Empty rule source")]), None

    if _INCLUDE_RE.search(source):
        return (
            CompileResult(
                ok=False,
                errors=[CompileError(
                    None, None,
                    "`include` directives are not allowed in playground rules",
                )],
            ),
            None,
        )

    import yara

    try:
        compiled = yara.compile(source=source)
    except yara.SyntaxError as e:
        line, col, message = _parse_yara_error(str(e))
        return CompileResult(ok=False, errors=[CompileError(line, col, message)]), None
    except yara.Error as e:
        return CompileResult(ok=False, errors=[CompileError(None, None, str(e))]), None
    except Exception as e:
        return CompileResult(ok=False, errors=[CompileError(None, None, str(e))]), None

    # yara-python doesn't expose rule count on a compiled bundle, count via a
    # cheap walk of the source — purely cosmetic for the UI.
    rules_count = len(re.findall(r"^\s*(?:private\s+|global\s+)*rule\s+\w+", source, re.MULTILINE))

    return CompileResult(ok=True, rules_count=rules_count), compiled


_YARA_ERR_RE = re.compile(r"line\s+(\d+)(?::(\d+))?\s*[:,-]?\s*(.*)", re.IGNORECASE)


def _parse_yara_error(msg: str) -> tuple[int | None, int | None, str]:
    """Best-effort parse of yara-python error strings into (line, col, msg)."""
    m = _YARA_ERR_RE.search(msg)
    if not m:
        return None, None, msg
    line = int(m.group(1)) if m.group(1) else None
    col = int(m.group(2)) if m.group(2) else None
    return line, col, m.group(3) or msg


def _safe_read_bytes(path: Path, max_bytes: int) -> bytes | None:
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes + 1)
        return data
    except OSError:
        return None


def _extract_string_match(
    data: bytes,
    identifier: str,
    offset: int,
    matched_bytes: bytes,
    context_bytes: int,
) -> StringMatch:
    """Build a StringMatch with limited context — never echo full file."""
    matched = _decode_safe(matched_bytes[: max(64, context_bytes)])
    if context_bytes <= 0:
        return StringMatch(identifier=identifier, offset=offset, matched=matched)
    start = max(0, offset - context_bytes)
    end = min(len(data), offset + len(matched_bytes) + context_bytes)
    before = _decode_safe(data[start:offset])
    after = _decode_safe(data[offset + len(matched_bytes):end])
    return StringMatch(
        identifier=identifier, offset=offset, matched=matched,
        context_before=before, context_after=after,
    )


def _decode_safe(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def _build_matches(
    yara_matches,
    *,
    data: bytes,
    target_kit_id: str | None,
    target_path: str,
    target_size: int,
    target_mime: str | None,
    include_strings: bool,
    context_bytes: int,
) -> list[Match]:
    out: list[Match] = []
    for m in yara_matches:
        strings: list[StringMatch] = []
        if include_strings:
            for s in m.strings[:20]:
                # yara-python's StringMatch object: identifier + instances list
                identifier = getattr(s, "identifier", "$")
                instances = getattr(s, "instances", None)
                if instances is not None:
                    for inst in instances[:10]:
                        offset = getattr(inst, "offset", 0)
                        matched_bytes = bytes(getattr(inst, "matched_data", b""))
                        strings.append(
                            _extract_string_match(
                                data, identifier, offset, matched_bytes, context_bytes,
                            )
                        )
                else:
                    # Older yara-python versions: tuple (offset, identifier, matched)
                    try:
                        offset, identifier_, matched_bytes = s
                        strings.append(
                            _extract_string_match(
                                data, identifier_, offset, bytes(matched_bytes), context_bytes,
                            )
                        )
                    except (TypeError, ValueError):
                        continue
        out.append(Match(
            rule=m.rule,
            namespace=m.namespace,
            tags=list(m.tags),
            meta=dict(m.meta),
            target_kit_id=target_kit_id,
            target_path=target_path,
            target_size=target_size,
            target_mime=target_mime,
            strings=strings,
        ))
    return out


def scan_bytes(
    rules,
    *,
    data: bytes,
    target_path: str,
    target_kit_id: str | None = None,
    target_mime: str | None = None,
    opts: ScanOpts | None = None,
) -> tuple[list[Match], bool]:
    """Scan a single in-memory buffer.  Returns (matches, errored)."""
    opts = (opts or ScanOpts()).clamp()
    try:
        yara_matches = rules.match(data=data, timeout=opts.timeout_seconds)
    except Exception as e:
        logger.warning("YARA scan_bytes failed for %s: %s", target_path, e)
        return [], True
    matches = _build_matches(
        yara_matches,
        data=data,
        target_kit_id=target_kit_id,
        target_path=target_path,
        target_size=len(data),
        target_mime=target_mime,
        include_strings=opts.include_strings,
        context_bytes=opts.string_context_bytes,
    )
    return matches, False


def scan_paths(
    rules,
    *,
    paths: list[tuple[Path, str | None, str]],  # (abs_path, kit_id, display_path)
    opts: ScanOpts | None = None,
) -> ScanResult:
    """Scan a list of disk paths.  ``display_path`` is what appears in results
    — typically a kit-relative path so we don't leak absolute filesystem paths.
    """
    opts = (opts or ScanOpts()).clamp()
    extensions = opts.extensions or PLAYGROUND_SCANNABLE_EXTENSIONS
    max_bytes = opts.max_file_size_mb * 1024 * 1024

    import time
    t0 = time.perf_counter()

    result = ScanResult()

    for abs_path, kit_id, display_path in paths:
        if result.files_scanned >= opts.max_files:
            break
        try:
            ext = abs_path.suffix.lower()
            basename = abs_path.name.lower()
            if ext not in extensions and basename != ".htaccess":
                result.files_skipped += 1
                continue
            if not abs_path.is_file():
                result.files_skipped += 1
                continue
            stat = abs_path.stat()
            if stat.st_size > max_bytes:
                result.files_skipped += 1
                continue
            data = _safe_read_bytes(abs_path, max_bytes)
            if data is None:
                result.target_errors.append(TargetError(display_path, "read failed"))
                continue
            mime, _ = mimetypes.guess_type(abs_path.name)
            matches, errored = scan_bytes(
                rules,
                data=data,
                target_path=display_path,
                target_kit_id=kit_id,
                target_mime=mime,
                opts=opts,
            )
            result.files_scanned += 1
            result.bytes_scanned += len(data)
            if errored:
                result.target_errors.append(TargetError(display_path, "scan timeout or error"))
            result.matches.extend(matches)
        except Exception as e:
            # Defensive — never let one bad file kill the whole scan.
            result.target_errors.append(TargetError(display_path, "skipped"))
            logger.debug("playground scan error on %s: %s", display_path, e)

    result.duration_ms = int((time.perf_counter() - t0) * 1000)
    return result


# Subdirectory under /app/downloads/{kit_id}/ that holds per-resource captures
# from a browser render — every JS/HTML/CSS/JSON the page loaded.  These are
# high-value YARA targets so we include them by default.
BROWSER_RESOURCES_SUBDIR = "_browser_resources"

# Subdirs / files inside the download dir that should NOT be scanned.
# ``_screenshots`` is binary PNGs; ``requests.json`` is the network log
# (no malicious payloads, just URL metadata that would clutter results).
DOWNLOAD_SKIP_NAMES: frozenset[str] = frozenset({"_screenshots", "requests.json"})


@dataclass
class FileEntry:
    relative_path: str
    size: int
    mime_type: str | None
    extension: str
    scannable: bool
    # Where the file lives — drives display in the UI and drives the
    # "display_path" prefix when scanning so analysts can tell whether a
    # match came from the unpacked archive vs the rendered page vs a
    # captured browser resource.
    source: str = "extracted"  # "extracted" | "raw" | "browser_resource"


def enumerate_kit_files(
    kit_extract_dir: str,
    kit_id: str,
    *,
    max_size_mb: int = MAX_FILE_SIZE_MB_CEILING,
    extensions: frozenset[str] | None = None,
) -> list[FileEntry]:
    """Walk a kit's extracted tree and return a file inventory.

    No file content is read here — only stat + extension classification.
    """
    base = Path(kit_extract_dir) / kit_id
    if not base.is_dir():
        return []

    ext_set = extensions or PLAYGROUND_SCANNABLE_EXTENSIONS
    max_bytes = max_size_mb * 1024 * 1024

    entries: list[FileEntry] = []
    for fp in sorted(base.rglob("*")):
        if not fp.is_file():
            continue
        try:
            size = fp.stat().st_size
        except OSError:
            continue
        ext = fp.suffix.lower()
        basename = fp.name.lower()
        scannable = (
            (ext in ext_set or basename == ".htaccess")
            and size <= max_bytes
        )
        mime, _ = mimetypes.guess_type(fp.name)
        try:
            rel = str(fp.relative_to(base))
        except ValueError:
            continue
        # Defense in depth: never let a symlink escape the kit dir leak out.
        try:
            resolved = fp.resolve()
            base_resolved = base.resolve()
            if not str(resolved).startswith(str(base_resolved)):
                continue
        except OSError:
            continue
        entries.append(FileEntry(
            relative_path=rel.replace(os.sep, "/"),
            size=size,
            mime_type=mime,
            extension=ext.lstrip("."),
            scannable=scannable,
        ))
    return entries


def kit_files_for_scan(
    kit_extract_dir: str,
    kit_id: str,
    *,
    relative_paths: list[str] | None = None,
) -> list[tuple[Path, str | None, str]]:
    """Resolve a list of relative paths under a kit's extract dir to
    absolute paths (with traversal protection).  If ``relative_paths`` is
    None, returns every file under the kit dir.
    """
    base = (Path(kit_extract_dir) / kit_id).resolve()
    if not base.is_dir():
        return []

    if relative_paths is None:
        out: list[tuple[Path, str | None, str]] = []
        for fp in base.rglob("*"):
            if fp.is_file():
                try:
                    rel = fp.relative_to(base)
                except ValueError:
                    continue
                out.append((fp, kit_id, rel.as_posix()))
        return out

    resolved: list[tuple[Path, str | None, str]] = []
    for rel in relative_paths:
        # Reject absolute, traversal, and weird inputs.
        if not rel or rel.startswith("/") or rel.startswith("\\") or ".." in Path(rel).parts:
            continue
        candidate = (base / rel).resolve()
        try:
            candidate.relative_to(base)
        except ValueError:
            continue
        if candidate.is_file():
            resolved.append((candidate, kit_id, rel.replace(os.sep, "/")))
    return resolved


# ---------------------------------------------------------------------------
# Multi-source enumeration — covers the three places kit content can live:
#
#   1. /app/extracted/{kit_id}/                 — unpacked archive contents
#   2. /app/downloads/{kit_id}/<file>           — raw download (kit.local_path)
#   3. /app/downloads/{kit_id}/_browser_resources/  — per-request captures
#                                                  from the rendered page
#
# Browser-rendered HTML kits (mime_type=text/html, ~54% of analyzed kits at
# time of writing) have NO extracted dir — their entire scannable surface is
# in the downloads dir.  Walking only /app/extracted/ misses them entirely,
# which is what the user hit with kit e2442aec-….
# ---------------------------------------------------------------------------


def _walk_dir_targets(
    base: Path,
    *,
    kit_id: str,
    source: str,
    display_prefix: str = "",
    extensions: frozenset[str] | None,
    max_bytes: int,
    skip_names: frozenset[str] = frozenset(),
) -> tuple[list[FileEntry], list[tuple[Path, str | None, str]]]:
    """Walk ``base`` and return (FileEntry inventory, scan-target tuples).

    The two outputs share the same files but in different shapes — the
    inventory drives /yara/scannable-files, the tuples feed scan_paths.
    Shared logic is what makes them produce a consistent view.
    """
    inventory: list[FileEntry] = []
    targets: list[tuple[Path, str | None, str]] = []
    if not base.is_dir():
        return inventory, targets

    try:
        base_resolved = base.resolve()
    except OSError:
        return inventory, targets

    ext_set = extensions or PLAYGROUND_SCANNABLE_EXTENSIONS

    for fp in sorted(base.rglob("*")):
        if not fp.is_file():
            continue
        try:
            rel = fp.relative_to(base)
        except ValueError:
            continue
        # Skip the noise dirs / files we never want to scan even when
        # they match the extension allowlist (e.g. requests.json).
        rel_parts = rel.parts
        if rel_parts and rel_parts[0] in skip_names:
            continue
        if fp.name in skip_names:
            continue

        # Symlink containment.
        try:
            resolved = fp.resolve()
            if not str(resolved).startswith(str(base_resolved)):
                continue
        except OSError:
            continue

        try:
            size = fp.stat().st_size
        except OSError:
            continue

        ext = fp.suffix.lower()
        basename = fp.name.lower()
        scannable = (
            (ext in ext_set or basename == ".htaccess")
            and size <= max_bytes
        )
        mime, _ = mimetypes.guess_type(fp.name)
        rel_posix = rel.as_posix().replace(os.sep, "/")
        display = f"{display_prefix}{rel_posix}" if display_prefix else rel_posix

        inventory.append(FileEntry(
            relative_path=display,
            size=size,
            mime_type=mime,
            extension=ext.lstrip("."),
            scannable=scannable,
            source=source,
        ))
        if scannable:
            targets.append((fp, kit_id, display))

    return inventory, targets


def _resolve_local_path_target(
    local_path: str | None,
    download_base: Path,
    *,
    kit_id: str,
    extensions: frozenset[str] | None,
    max_bytes: int,
) -> tuple[FileEntry | None, tuple[Path, str | None, str] | None]:
    """Add the kit's raw download (``kit.local_path``) as a scan target.

    Skipped if local_path is missing, escapes the download dir (defense
    against absolute paths from a hostile DB row), or is the same file
    we'd already pick up by walking ``/app/downloads/{kit_id}/`` — the
    walker covers it via the inventory loop, but we still want to mark
    it as ``source="raw"`` for clarity in the UI.
    """
    if not local_path:
        return None, None
    fp = Path(local_path)
    if not fp.is_file():
        return None, None
    try:
        fp_resolved = fp.resolve()
        base_resolved = download_base.resolve()
        if not str(fp_resolved).startswith(str(base_resolved)):
            return None, None
        rel = fp_resolved.relative_to(base_resolved).as_posix()
    except (OSError, ValueError):
        return None, None
    try:
        size = fp.stat().st_size
    except OSError:
        return None, None

    ext = fp.suffix.lower()
    basename = fp.name.lower()
    ext_set = extensions or PLAYGROUND_SCANNABLE_EXTENSIONS
    scannable = (
        (ext in ext_set or basename == ".htaccess")
        and size <= max_bytes
    )
    mime, _ = mimetypes.guess_type(fp.name)
    display = rel  # already kit-id-prefixed since base = download_base/kit_id
    entry = FileEntry(
        relative_path=display,
        size=size,
        mime_type=mime,
        extension=ext.lstrip("."),
        scannable=scannable,
        source="raw",
    )
    target = (fp, kit_id, display) if scannable else None
    return entry, target


def enumerate_kit_scan_targets(
    *,
    kit_id: str,
    local_path: str | None,
    extract_dir: str,
    download_dir: str,
    extensions: frozenset[str] | None = None,
    max_size_mb: int = MAX_FILE_SIZE_MB_CEILING,
    relative_paths: list[str] | None = None,
) -> tuple[list[FileEntry], list[tuple[Path, str | None, str]]]:
    """Resolve every scannable file across all storage locations for a kit.

    Returns ``(inventory, scan_targets)``:
      - ``inventory`` — every file (scannable + non-scannable) for the
        /yara/scannable-files response.
      - ``scan_targets`` — the (path, kit_id, display_path) tuples to
        feed to ``scan_paths``.

    When ``relative_paths`` is provided, only those files are returned —
    they're resolved against either the extracted dir or the downloads
    dir based on which exists, with traversal protection.
    """
    max_bytes = max_size_mb * 1024 * 1024
    extract_base = (Path(extract_dir) / kit_id).resolve()
    download_base = (Path(download_dir) / kit_id).resolve()

    # Constrained mode — analyst picked specific files in the UI.
    if relative_paths is not None:
        targets: list[tuple[Path, str | None, str]] = []
        for rel in relative_paths:
            if not rel or rel.startswith(("/", "\\")) or ".." in Path(rel).parts:
                continue
            for base in (extract_base, download_base):
                if not base.is_dir():
                    continue
                candidate = (base / rel).resolve()
                try:
                    candidate.relative_to(base)
                except ValueError:
                    continue
                if candidate.is_file():
                    targets.append((candidate, kit_id, rel.replace(os.sep, "/")))
                    break
        return [], targets

    # Default mode — full inventory across all sources.
    full_inventory: list[FileEntry] = []
    full_targets: list[tuple[Path, str | None, str]] = []

    # 1. Extracted tree (no display prefix — keep the existing path shape
    #    so saved scans stay stable).
    inv, tgts = _walk_dir_targets(
        extract_base,
        kit_id=kit_id, source="extracted",
        display_prefix="",
        extensions=extensions, max_bytes=max_bytes,
    )
    full_inventory.extend(inv)
    full_targets.extend(tgts)

    seen_paths: set[Path] = {Path(t[0]).resolve() for t in full_targets}

    # 2. Browser-resources subdirectory (rendered-page captures).
    browser_base = download_base / BROWSER_RESOURCES_SUBDIR
    inv, tgts = _walk_dir_targets(
        browser_base,
        kit_id=kit_id, source="browser_resource",
        display_prefix=f"{BROWSER_RESOURCES_SUBDIR}/",
        extensions=extensions, max_bytes=max_bytes,
    )
    full_inventory.extend(inv)
    for t in tgts:
        rp = Path(t[0]).resolve()
        if rp not in seen_paths:
            full_targets.append(t)
            seen_paths.add(rp)

    # 3. Raw download via kit.local_path — typically the rendered
    #    ``page.html`` or a single-file artifact like ``download.bin``.
    raw_entry, raw_target = _resolve_local_path_target(
        local_path, download_base,
        kit_id=kit_id, extensions=extensions, max_bytes=max_bytes,
    )
    if raw_entry is not None:
        full_inventory.append(raw_entry)
        if raw_target is not None:
            rp = Path(raw_target[0]).resolve()
            if rp not in seen_paths:
                full_targets.append(raw_target)
                seen_paths.add(rp)

    return full_inventory, full_targets
