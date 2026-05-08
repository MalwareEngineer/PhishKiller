"""Unit tests for the YARA playground module.

Skipped automatically when ``yara-python`` is not installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from darla.analysis.yara_playground import (
    PLAYGROUND_SCANNABLE_EXTENSIONS,
    ScanOpts,
    compile_source,
    enumerate_kit_files,
    is_yara_available,
    kit_files_for_scan,
    scan_bytes,
    scan_paths,
)

pytestmark = pytest.mark.skipif(
    not is_yara_available(),
    reason="yara-python not installed",
)


SIMPLE_RULE = """
rule hello {
    strings:
        $a = "hello"
    condition:
        $a
}
"""

BROKEN_RULE = """
rule oops {
    strings:
        $a = "hi
    condition:
        $a
}
"""

INCLUDE_RULE = """
include "other.yar"
rule x { condition: true }
"""


def test_compile_success():
    result, compiled = compile_source(SIMPLE_RULE)
    assert result.ok is True
    assert result.rules_count == 1
    assert result.errors == []
    assert compiled is not None


def test_compile_syntax_error_surfaces_message():
    result, compiled = compile_source(BROKEN_RULE)
    assert result.ok is False
    assert compiled is None
    assert len(result.errors) == 1
    # Don't assert exact line — yara error formats vary across versions.
    assert result.errors[0].message


def test_compile_rejects_include():
    result, compiled = compile_source(INCLUDE_RULE)
    assert result.ok is False
    assert compiled is None
    assert "include" in result.errors[0].message.lower()


@pytest.mark.parametrize("module_src", [
    'import "pe"\nrule x { condition: pe.is_pe }',
    'import "dotnet"\nrule x { condition: dotnet.is_dotnet }',
    'import "math"\nrule x { condition: math.entropy(0, filesize) > 7 }',
    'import "hash"\nrule x { condition: hash.md5(0, filesize) == '
    '"d41d8cd98f00b204e9800998ecf8427e" }',
])
def test_compile_allows_module_imports(module_src: str):
    """``import`` (modules like pe, dotnet, math, hash) is distinct from
    ``include`` (file-system rule loading) — playground rules must be
    able to use modules even though we block include directives.
    """
    result, compiled = compile_source(module_src)
    assert result.ok is True, [e.message for e in result.errors]
    assert compiled is not None


def test_compile_rejects_empty():
    result, _ = compile_source("")
    assert result.ok is False
    assert result.errors[0].message


def test_scan_bytes_match_with_context():
    _, compiled = compile_source(SIMPLE_RULE)
    data = b"goodbye world hello there"
    matches, errored = scan_bytes(
        compiled, data=data, target_path="paste.txt",
        opts=ScanOpts(string_context_bytes=8),
    )
    assert errored is False
    assert len(matches) == 1
    m = matches[0]
    assert m.rule == "hello"
    assert m.target_path == "paste.txt"
    assert m.target_size == len(data)
    assert m.strings, "expected at least one string match"
    s = m.strings[0]
    assert s.matched.startswith("hello")
    # Context preview should not echo the entire buffer.
    assert len(s.context_before) <= 8
    assert len(s.context_after) <= 8


def test_scan_bytes_no_match():
    _, compiled = compile_source(SIMPLE_RULE)
    matches, errored = scan_bytes(
        compiled, data=b"nothing relevant here", target_path="paste.txt",
    )
    assert errored is False
    assert matches == []


def test_scan_paths_walks_extracted_kit(tmp_path: Path):
    _, compiled = compile_source(SIMPLE_RULE)
    kit_id = "fake-kit-1"
    base = tmp_path / kit_id
    (base / "sub").mkdir(parents=True)
    (base / "match.html").write_text("<html>hello world</html>")
    (base / "skip.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
    (base / "sub" / "other.js").write_text("console.log('bye')")

    targets = kit_files_for_scan(str(tmp_path), kit_id)
    assert len(targets) == 3  # all files included; extension filter happens in scan_paths

    result = scan_paths(compiled, paths=targets, opts=ScanOpts())
    assert result.files_scanned >= 1  # html scanned
    assert result.files_skipped >= 1  # png skipped
    assert any(m.target_path == "match.html" for m in result.matches)
    assert all(m.target_kit_id == kit_id for m in result.matches)


def test_scan_paths_respects_max_files(tmp_path: Path):
    _, compiled = compile_source(SIMPLE_RULE)
    kit_id = "kid"
    base = tmp_path / kit_id
    base.mkdir(parents=True)
    for i in range(20):
        (base / f"f{i}.html").write_text("hello x")
    targets = kit_files_for_scan(str(tmp_path), kit_id)
    result = scan_paths(compiled, paths=targets, opts=ScanOpts(max_files=5))
    assert result.files_scanned == 5


def test_scan_paths_respects_max_file_size(tmp_path: Path):
    _, compiled = compile_source(SIMPLE_RULE)
    kit_id = "kid"
    base = tmp_path / kit_id
    base.mkdir(parents=True)
    big = b"hello " + b"x" * (2 * 1024 * 1024)  # 2MB
    (base / "big.html").write_bytes(big)
    targets = kit_files_for_scan(str(tmp_path), kit_id)
    result = scan_paths(compiled, paths=targets, opts=ScanOpts(max_file_size_mb=1))
    assert result.files_scanned == 0
    assert result.files_skipped == 1


def test_kit_files_for_scan_rejects_traversal(tmp_path: Path):
    kit_id = "kid"
    base = tmp_path / kit_id
    base.mkdir(parents=True)
    (base / "ok.html").write_text("hi")
    (tmp_path / "outside.txt").write_text("secret")

    # Try to escape via ..
    targets = kit_files_for_scan(
        str(tmp_path), kit_id, relative_paths=["../outside.txt", "ok.html"],
    )
    paths = [t[2] for t in targets]
    assert "ok.html" in paths
    assert not any("outside" in p for p in paths)


def test_kit_files_for_scan_rejects_absolute(tmp_path: Path):
    kit_id = "kid"
    base = tmp_path / kit_id
    base.mkdir(parents=True)
    (base / "ok.html").write_text("hi")

    targets = kit_files_for_scan(
        str(tmp_path), kit_id, relative_paths=["/etc/passwd", "C:\\Windows\\notepad.exe"],
    )
    assert targets == []


def test_enumerate_kit_files_classifies_scannable(tmp_path: Path):
    kit_id = "kid"
    base = tmp_path / kit_id
    (base / "sub").mkdir(parents=True)
    (base / "page.html").write_text("hi")
    (base / "image.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (base / ".htaccess").write_text("RewriteRule ^.*$ index.php")

    files = enumerate_kit_files(str(tmp_path), kit_id)
    by_path = {f.relative_path: f for f in files}
    assert by_path["page.html"].scannable is True
    assert by_path["image.png"].scannable is False
    assert by_path[".htaccess"].scannable is True


def test_enumerate_kit_files_returns_empty_for_missing_kit(tmp_path: Path):
    assert enumerate_kit_files(str(tmp_path), "no-such-kit") == []


def test_extensions_filter_clamped_to_allowlist(tmp_path: Path):
    # User passes ".exe" which isn't in the allowlist — scan_paths should
    # silently skip it.  (api/yara.py performs the clamp; we test the
    # path enforcement here.)
    _, compiled = compile_source(SIMPLE_RULE)
    kit_id = "kid"
    base = tmp_path / kit_id
    base.mkdir(parents=True)
    (base / "x.exe").write_text("hello")

    targets = kit_files_for_scan(str(tmp_path), kit_id)
    result = scan_paths(
        compiled, paths=targets,
        opts=ScanOpts(extensions=frozenset({".html"})),
    )
    assert result.files_scanned == 0


def test_default_extensions_constant_is_frozenset():
    assert isinstance(PLAYGROUND_SCANNABLE_EXTENSIONS, frozenset)
    assert ".html" in PLAYGROUND_SCANNABLE_EXTENSIONS
    assert ".php" in PLAYGROUND_SCANNABLE_EXTENSIONS


# ── Multi-source enumeration (extracted + raw + browser_resources) ──

from darla.analysis.yara_playground import enumerate_kit_scan_targets  # noqa: E402


def _scaffold_kit_dirs(tmp_path: Path, kit_id: str):
    """Build matching extract/download dirs for a synthetic kit."""
    extract_dir = tmp_path / "extracted"
    download_dir = tmp_path / "downloads"
    extract_kit = extract_dir / kit_id
    download_kit = download_dir / kit_id
    extract_dir.mkdir()
    download_dir.mkdir()
    return extract_dir, download_dir, extract_kit, download_kit


def test_enumerate_finds_extracted_files(tmp_path: Path):
    """Smoke test: pure-extracted kit (existing Phase 1 behaviour)."""
    extract_dir, download_dir, extract_kit, _ = _scaffold_kit_dirs(tmp_path, "kid")
    extract_kit.mkdir()
    (extract_kit / "index.php").write_text("<?php echo 'hi'; ?>")
    (extract_kit / "skip.png").write_bytes(b"\x89PNG")

    inv, tgts = enumerate_kit_scan_targets(
        kit_id="kid", local_path=None,
        extract_dir=str(extract_dir), download_dir=str(download_dir),
    )
    assert any(f.relative_path == "index.php" and f.source == "extracted" for f in inv)
    assert {t[2] for t in tgts} == {"index.php"}  # png excluded by extension filter


def test_enumerate_finds_raw_local_path(tmp_path: Path):
    """Browser-rendered HTML kit — only ``page.html`` exists, no extracted dir.

    This is the user's reported bug: kit e2442aec-… had `page.html` in
    /app/downloads but nothing in /app/extracted, so 0 files scanned.
    """
    extract_dir, download_dir, _, download_kit = _scaffold_kit_dirs(tmp_path, "kid")
    download_kit.mkdir()
    page = download_kit / "page.html"
    page.write_text("<html>hello world</html>")

    inv, tgts = enumerate_kit_scan_targets(
        kit_id="kid", local_path=str(page),
        extract_dir=str(extract_dir), download_dir=str(download_dir),
    )
    raw_entries = [f for f in inv if f.source == "raw"]
    assert len(raw_entries) == 1
    assert raw_entries[0].relative_path == "page.html"
    assert any(t[2] == "page.html" for t in tgts), "page.html should be a scan target"


def test_enumerate_finds_browser_resources(tmp_path: Path):
    """The captured network resources — every JS/HTML/CSS the page loaded."""
    extract_dir, download_dir, _, download_kit = _scaffold_kit_dirs(tmp_path, "kid")
    br = download_kit / "_browser_resources"
    br.mkdir(parents=True)
    (br / "001_loader.js").write_text("eval(atob('hello'))")
    (br / "002_payload.html").write_text("<form>cred</form>")

    inv, tgts = enumerate_kit_scan_targets(
        kit_id="kid", local_path=None,
        extract_dir=str(extract_dir), download_dir=str(download_dir),
    )
    br_entries = [f for f in inv if f.source == "browser_resource"]
    assert len(br_entries) == 2
    paths = {t[2] for t in tgts}
    assert "_browser_resources/001_loader.js" in paths
    assert "_browser_resources/002_payload.html" in paths


def test_enumerate_skips_screenshots_and_requests_json(tmp_path: Path):
    """``_screenshots/`` (PNGs) and ``requests.json`` (network log) must
    never be scanned — they're not malware payloads, just metadata.
    """
    extract_dir, download_dir, _, download_kit = _scaffold_kit_dirs(tmp_path, "kid")
    download_kit.mkdir()
    page = download_kit / "page.html"
    page.write_text("<html></html>")
    (download_kit / "_screenshots").mkdir()
    (download_kit / "_screenshots" / "01_landing.png").write_bytes(b"PNG")
    (download_kit / "requests.json").write_text('[{"url": "https://example.com"}]')

    inv, _ = enumerate_kit_scan_targets(
        kit_id="kid", local_path=str(page),
        extract_dir=str(extract_dir), download_dir=str(download_dir),
    )
    paths = {f.relative_path for f in inv}
    assert not any("screenshots" in p for p in paths)
    assert not any("requests.json" in p for p in paths)


def test_enumerate_combines_all_three_sources(tmp_path: Path):
    """A kit can have extracted files + raw page.html + browser resources
    all at once.  All three should appear in the inventory.
    """
    extract_dir, download_dir, extract_kit, download_kit = _scaffold_kit_dirs(tmp_path, "kid")
    extract_kit.mkdir()
    (extract_kit / "extracted_marker.php").write_text("hi")
    download_kit.mkdir()
    page = download_kit / "page.html"
    page.write_text("hi")
    br = download_kit / "_browser_resources"
    br.mkdir()
    (br / "001_loader.js").write_text("hi")

    inv, _ = enumerate_kit_scan_targets(
        kit_id="kid", local_path=str(page),
        extract_dir=str(extract_dir), download_dir=str(download_dir),
    )
    sources = {f.source for f in inv}
    assert sources == {"extracted", "raw", "browser_resource"}


def test_enumerate_dedupes_when_local_path_in_browser_walk(tmp_path: Path):
    """If local_path points to a file under download_dir/{kit}/ that we
    also walked via browser_resources, we shouldn't get two scan targets
    for the same physical file.
    """
    extract_dir, download_dir, _, download_kit = _scaffold_kit_dirs(tmp_path, "kid")
    download_kit.mkdir()
    page = download_kit / "page.html"
    page.write_text("hi")

    _, tgts = enumerate_kit_scan_targets(
        kit_id="kid", local_path=str(page),
        extract_dir=str(extract_dir), download_dir=str(download_dir),
    )
    raw_targets = [t for t in tgts if t[2] == "page.html"]
    assert len(raw_targets) == 1


def test_enumerate_rejects_local_path_outside_download_dir(tmp_path: Path):
    """Defense in depth: a hostile/corrupted DB row pointing kit.local_path
    at /etc/passwd must not be scannable.
    """
    extract_dir, download_dir, _, _ = _scaffold_kit_dirs(tmp_path, "kid")
    rogue = tmp_path / "outside.html"
    rogue.write_text("<html>secret</html>")

    inv, tgts = enumerate_kit_scan_targets(
        kit_id="kid", local_path=str(rogue),
        extract_dir=str(extract_dir), download_dir=str(download_dir),
    )
    assert inv == []
    assert tgts == []


def test_enumerate_returns_empty_for_kit_with_nothing(tmp_path: Path):
    extract_dir = tmp_path / "extracted"
    download_dir = tmp_path / "downloads"
    extract_dir.mkdir()
    download_dir.mkdir()
    inv, tgts = enumerate_kit_scan_targets(
        kit_id="missing", local_path=None,
        extract_dir=str(extract_dir), download_dir=str(download_dir),
    )
    assert inv == []
    assert tgts == []


def test_enumerate_relative_paths_resolves_against_either_dir(tmp_path: Path):
    """When the analyst picks specific files, we should resolve them
    against extracted dir first and fall back to downloads dir.
    """
    extract_dir, download_dir, extract_kit, download_kit = _scaffold_kit_dirs(tmp_path, "kid")
    extract_kit.mkdir()
    (extract_kit / "from_extract.php").write_text("hi")
    download_kit.mkdir()
    (download_kit / "page.html").write_text("hi")

    _, tgts = enumerate_kit_scan_targets(
        kit_id="kid", local_path=None,
        extract_dir=str(extract_dir), download_dir=str(download_dir),
        relative_paths=["from_extract.php", "page.html", "../escape.txt"],
    )
    paths = {t[2] for t in tgts}
    assert "from_extract.php" in paths
    assert "page.html" in paths
    assert not any("escape" in p for p in paths)
