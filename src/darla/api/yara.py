"""YARA playground API.

In-app rule authoring + testing surface.  All endpoints are read-only
against the production rules directory; user rules saving is Phase 2.

Sandboxing summary:
- Compile rejects ``include`` directives.
- Per-scan timeout enforced via yara-python's ``timeout=`` arg, plus a
  thread wall-clock ceiling.
- Hard ceilings on file count, per-file size, and total bytes.
- Path traversal guarded in ``yara_playground.kit_files_for_scan``.

No PII leaves the server beyond what the analyst supplied:
- Logs record kit IDs, rule counts, durations — never rule source bodies
  or matched bytes.
- Match string previews are clamped to ``string_context_bytes`` (max 256).
"""

from __future__ import annotations

import asyncio
import logging
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from fastapi import APIRouter, HTTPException

from darla.analysis.yara_playground import (
    PLAYGROUND_SCANNABLE_EXTENSIONS,
    CompileResult,
    Match,
    ScanOpts,
    ScanResult,
    TargetError,
    compile_source,
    enumerate_kit_files,
    is_yara_available,
    kit_files_for_scan,
    scan_bytes,
    scan_paths,
)
from darla.config import get_settings
from darla.schemas.yara import (
    CompileErrorOut,
    CompileRequest,
    CompileResultOut,
    MatchOut,
    PlaygroundRequest,
    PlaygroundResponse,
    RuleFileSource,
    RuleFileSummary,
    ScannableFile,
    ScannableFilesResponse,
    ScanOptionsIn,
    ScanStats,
    StringMatchOut,
    TargetErrorOut,
    YaraStatusResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter()


# Single executor reused across requests — playground scans are
# short-lived and each request runs at most one task on it.
_SCAN_EXECUTOR = ThreadPoolExecutor(max_workers=4, thread_name_prefix="yara-playground")

# Conservative wall-clock multiplier above the user-configured timeout.
# Defends against pathological rules that bypass yara's internal timer.
_WALLCLOCK_GRACE_SECONDS = 5

_RULE_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]+$")


def _ensure_available() -> None:
    if not is_yara_available():
        raise HTTPException(
            status_code=503,
            detail=(
                "yara-python is not installed in this environment. "
                "Install it with `pip install darla[yara]`."
            ),
        )


def _to_compile_out(result: CompileResult) -> CompileResultOut:
    return CompileResultOut(
        ok=result.ok,
        rules_count=result.rules_count,
        errors=[CompileErrorOut(line=e.line, column=e.column, message=e.message)
                for e in result.errors],
        warnings=list(result.warnings),
    )


def _to_match_out(m: Match) -> MatchOut:
    return MatchOut(
        rule=m.rule,
        namespace=m.namespace,
        tags=list(m.tags),
        meta={k: _safe_meta_val(v) for k, v in m.meta.items()},
        target_kit_id=m.target_kit_id,
        target_path=m.target_path,
        target_size=m.target_size,
        target_mime=m.target_mime,
        strings=[
            StringMatchOut(
                identifier=s.identifier,
                offset=s.offset,
                matched=s.matched,
                context_before=s.context_before,
                context_after=s.context_after,
            )
            for s in m.strings
        ],
    )


def _safe_meta_val(v):
    """yara meta values can be bytes/bool/int/str — make them JSON-safe."""
    if isinstance(v, bytes):
        try:
            return v.decode("utf-8", errors="replace")
        except Exception:
            return repr(v)
    return v


def _opts_from_in(o: ScanOptionsIn) -> ScanOpts:
    extensions: frozenset[str] | None = None
    if o.extensions:
        # Normalize to lowercase with leading dot, intersect with allowlist.
        cleaned = {
            ("." + e.lstrip(".")).lower()
            for e in o.extensions
            if e and len(e) <= 16
        }
        extensions = frozenset(cleaned & PLAYGROUND_SCANNABLE_EXTENSIONS)
        # If the analyst's filter is fully outside the allowlist, fall
        # back to defaults rather than scanning nothing silently.
        if not extensions:
            extensions = None
    return ScanOpts(
        timeout_seconds=o.timeout_seconds,
        max_files=o.max_files,
        max_file_size_mb=o.max_file_size_mb,
        include_strings=o.include_strings,
        string_context_bytes=o.string_context_bytes,
        extensions=extensions,
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/status", response_model=YaraStatusResponse)
async def yara_status():
    settings = get_settings()
    rules_path = Path(settings.yara_rules_dir)
    builtin = 0
    if rules_path.is_dir():
        builtin = sum(1 for _ in rules_path.glob("**/*.yar")) + sum(
            1 for _ in rules_path.glob("**/*.yara")
        )
    return YaraStatusResponse(
        available=is_yara_available(),
        rules_dir=str(rules_path),
        builtin_rule_files=builtin,
    )


@router.post("/compile", response_model=CompileResultOut)
async def compile_rule(req: CompileRequest):
    _ensure_available()
    result, _ = compile_source(req.rule_source)
    logger.info(
        "yara playground compile: ok=%s errors=%d rules=%d",
        result.ok, len(result.errors), result.rules_count,
    )
    return _to_compile_out(result)


@router.post("/playground", response_model=PlaygroundResponse)
async def playground_scan(req: PlaygroundRequest):
    _ensure_available()

    if not req.kits and not req.raw:
        raise HTTPException(
            status_code=400,
            detail="At least one target (kits or raw) is required",
        )

    compile_result, compiled = compile_source(req.rule_source)
    if not compile_result.ok or compiled is None:
        return PlaygroundResponse(
            compile=_to_compile_out(compile_result),
            stats=ScanStats(),
            matches=[],
            target_errors=[],
        )

    opts = _opts_from_in(req.options)
    settings = get_settings()

    def _run() -> ScanResult:
        merged = ScanResult()

        # Resolve kit-file targets.
        path_targets: list[tuple[Path, str | None, str]] = []
        for kt in req.kits[:50]:  # also cap on number of kits
            rels = kt.relative_paths or None
            path_targets.extend(
                kit_files_for_scan(
                    settings.kit_extract_dir, kt.kit_id, relative_paths=rels,
                )
            )

        if path_targets:
            r = scan_paths(compiled, paths=path_targets, opts=opts)
            _merge(merged, r)

        # Raw paste targets — always scan after disk targets so caps apply
        # consistently.
        for raw in req.raw[:20]:
            if merged.files_scanned >= opts.max_files:
                break
            data = raw.content.encode("utf-8", errors="replace")
            if len(data) > opts.max_file_size_mb * 1024 * 1024:
                merged.target_errors.append(
                    TargetError(target=raw.name, error="exceeds max_file_size_mb")
                )
                merged.files_skipped += 1
                continue
            matches, errored = scan_bytes(
                compiled,
                data=data,
                target_path=raw.name,
                target_kit_id=None,
                target_mime="text/plain",
                opts=opts,
            )
            merged.files_scanned += 1
            merged.bytes_scanned += len(data)
            if errored:
                merged.target_errors.append(
                    TargetError(target=raw.name, error="scan timeout or error")
                )
            merged.matches.extend(matches)
        return merged

    # Wall-clock guard.  yara-python's internal timeout normally fires first;
    # this is belt-and-suspenders against pathological scans.
    wallclock = (
        opts.timeout_seconds * max(1, len(req.kits) + len(req.raw))
        + _WALLCLOCK_GRACE_SECONDS
    )
    loop = asyncio.get_event_loop()
    try:
        result = await asyncio.wait_for(
            loop.run_in_executor(_SCAN_EXECUTOR, _run),
            timeout=wallclock,
        )
    except TimeoutError:
        logger.warning(
            "yara playground wall-clock timeout: kits=%d raw=%d wallclock=%ds",
            len(req.kits), len(req.raw), wallclock,
        )
        raise HTTPException(
            status_code=408,
            detail=(
                f"Scan exceeded wall-clock budget ({wallclock}s). "
                "Reduce target count or rule complexity."
            ),
        ) from None

    logger.info(
        "yara playground scan: kits=%d raw=%d files=%d bytes=%d matches=%d duration_ms=%d",
        len(req.kits), len(req.raw),
        result.files_scanned, result.bytes_scanned,
        len(result.matches), result.duration_ms,
    )

    return PlaygroundResponse(
        compile=_to_compile_out(compile_result),
        stats=ScanStats(
            files_scanned=result.files_scanned,
            files_skipped=result.files_skipped,
            bytes_scanned=result.bytes_scanned,
            duration_ms=result.duration_ms,
        ),
        matches=[_to_match_out(m) for m in result.matches],
        target_errors=[
            TargetErrorOut(target=e.target, error=e.error)
            for e in result.target_errors
        ],
    )


def _merge(into: ScanResult, src: ScanResult) -> None:
    into.matches.extend(src.matches)
    into.files_scanned += src.files_scanned
    into.files_skipped += src.files_skipped
    into.bytes_scanned += src.bytes_scanned
    into.duration_ms += src.duration_ms
    into.target_errors.extend(src.target_errors)


@router.get("/rules", response_model=list[RuleFileSummary])
async def list_rules():
    """List installed YARA rule files (read-only).  Excludes ``rules/user/``
    which is Phase 2.
    """
    settings = get_settings()
    rules_path = Path(settings.yara_rules_dir)
    if not rules_path.is_dir():
        return []

    out: list[RuleFileSummary] = []
    for fp in sorted(rules_path.rglob("*")):
        if not fp.is_file() or fp.suffix.lower() not in (".yar", ".yara"):
            continue
        try:
            rel = fp.relative_to(rules_path).as_posix()
        except ValueError:
            continue
        # Tag third-party (t4d submodule) so the UI can colour it differently.
        source_kind = "third_party" if rel.startswith("t4d/") else "builtin"
        try:
            text = fp.read_text(errors="replace")
        except OSError:
            continue
        rule_count = len(re.findall(
            r"^\s*(?:private\s+|global\s+)*rule\s+\w+", text, re.MULTILINE,
        ))
        try:
            size = fp.stat().st_size
        except OSError:
            size = len(text)
        out.append(RuleFileSummary(
            name=fp.stem,
            relative_path=rel,
            size=size,
            rule_count=rule_count,
            source=source_kind,
        ))
    return out


@router.get("/rules/{name:path}", response_model=RuleFileSource)
async def get_rule(name: str):
    """Read a rule file's source for editor pre-fill."""
    settings = get_settings()
    rules_path = Path(settings.yara_rules_dir).resolve()

    # Path-traversal hardening: forbid ``..`` and absolute, then verify the
    # resolved path stays under rules_path.
    if not name or ".." in Path(name).parts or name.startswith(("/", "\\")):
        raise HTTPException(status_code=400, detail="Invalid rule name")

    # Accept either bare stem (e.g. ``evasion``) or relative path with
    # extension (``t4d/foo.yar``).
    candidate: Path | None = None
    direct = (rules_path / name).resolve()
    try:
        direct.relative_to(rules_path)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid rule name") from None

    if direct.is_file() and direct.suffix.lower() in (".yar", ".yara"):
        candidate = direct
    else:
        # Search for a matching stem.
        for ext in (".yar", ".yara"):
            guess = (rules_path / f"{name}{ext}").resolve()
            try:
                guess.relative_to(rules_path)
            except ValueError:
                continue
            if guess.is_file():
                candidate = guess
                break

    if candidate is None:
        raise HTTPException(status_code=404, detail="Rule file not found")

    try:
        rel = candidate.relative_to(rules_path).as_posix()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid rule path") from None

    source_kind = "third_party" if rel.startswith("t4d/") else "builtin"
    try:
        content = candidate.read_text(errors="replace")
    except OSError as e:
        raise HTTPException(status_code=500, detail=f"Read failed: {e}") from None

    return RuleFileSource(
        name=candidate.stem,
        relative_path=rel,
        source=source_kind,
        content=content,
    )


@router.get("/scannable-files/{kit_id}", response_model=ScannableFilesResponse)
async def scannable_files(kit_id: str, max_size_mb: int = 100):
    """Return the file inventory for a kit's extracted tree."""
    # Light validation — kit IDs are UUID strings; reject anything else
    # to prevent path-shaped inputs reaching enumerate_kit_files.
    if not _RULE_NAME_RE.match(kit_id.replace("-", "")) or len(kit_id) > 64:
        raise HTTPException(status_code=400, detail="Invalid kit_id")

    settings = get_settings()
    files = enumerate_kit_files(
        settings.kit_extract_dir,
        kit_id,
        max_size_mb=min(max(1, max_size_mb), 100),
    )
    return ScannableFilesResponse(
        kit_id=kit_id,
        files=[
            ScannableFile(
                relative_path=f.relative_path,
                size=f.size,
                mime_type=f.mime_type,
                extension=f.extension,
                scannable=f.scannable,
            )
            for f in files
        ],
        total=len(files),
        scannable_count=sum(1 for f in files if f.scannable),
    )
