"""Pydantic schemas for the YARA playground API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class CompileErrorOut(BaseModel):
    line: int | None = None
    column: int | None = None
    message: str


class CompileResultOut(BaseModel):
    ok: bool
    rules_count: int = 0
    errors: list[CompileErrorOut] = []
    warnings: list[str] = []


class CompileRequest(BaseModel):
    rule_source: str = Field(..., max_length=200_000)


class StringMatchOut(BaseModel):
    identifier: str
    offset: int
    matched: str
    context_before: str = ""
    context_after: str = ""


class MatchOut(BaseModel):
    rule: str
    namespace: str
    tags: list[str]
    meta: dict
    target_kit_id: str | None = None
    target_path: str
    target_size: int
    target_mime: str | None = None
    strings: list[StringMatchOut] = []


class TargetErrorOut(BaseModel):
    target: str
    error: str


class ScanStats(BaseModel):
    files_scanned: int = 0
    files_skipped: int = 0
    bytes_scanned: int = 0
    duration_ms: int = 0


class ScanOptionsIn(BaseModel):
    timeout_seconds: int = Field(10, ge=1, le=60)
    max_files: int = Field(500, ge=1, le=5000)
    max_file_size_mb: int = Field(10, ge=1, le=100)
    include_strings: bool = True
    string_context_bytes: int = Field(64, ge=0, le=256)
    # Optional analyst-controlled filter — extensions without leading dot.
    # Empty list means "use server defaults".
    extensions: list[str] = []


class KitTargetIn(BaseModel):
    kit_id: str
    # When None / empty, scan every scannable file under the kit.
    relative_paths: list[str] = []


class RawTargetIn(BaseModel):
    name: str = Field(..., max_length=200)
    # Plain text only.  Paste tab is for analyst snippets, not binaries —
    # uploads (Phase 2) will use a separate endpoint.
    content: str = Field(..., max_length=2_000_000)


class PlaygroundRequest(BaseModel):
    rule_source: str = Field(..., max_length=200_000)
    kits: list[KitTargetIn] = []
    raw: list[RawTargetIn] = []
    options: ScanOptionsIn = ScanOptionsIn()


class PlaygroundResponse(BaseModel):
    compile: CompileResultOut
    stats: ScanStats
    matches: list[MatchOut] = []
    target_errors: list[TargetErrorOut] = []


class RuleFileSummary(BaseModel):
    name: str          # stem (no extension)
    relative_path: str
    size: int
    rule_count: int
    source: str        # "builtin" | "third_party"


class RuleFileSource(BaseModel):
    name: str
    relative_path: str
    source: str
    content: str


class ScannableFile(BaseModel):
    relative_path: str
    size: int
    mime_type: str | None = None
    extension: str
    scannable: bool


class ScannableFilesResponse(BaseModel):
    kit_id: str
    files: list[ScannableFile]
    total: int
    scannable_count: int


class YaraStatusResponse(BaseModel):
    available: bool
    rules_dir: str
    builtin_rule_files: int
