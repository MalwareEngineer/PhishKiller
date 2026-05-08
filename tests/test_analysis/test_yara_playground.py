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
    'import "hash"\nrule x { condition: hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e" }',
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
