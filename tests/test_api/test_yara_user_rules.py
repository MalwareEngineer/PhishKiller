"""Tests for the YARA playground save/delete/upload endpoints (Phase 2).

Uses FastAPI's TestClient + a tmp rules dir override.  Skipped when
yara-python is not installed.
"""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from darla.analysis.yara_playground import is_yara_available
from darla.api.yara import router as yara_router
from darla.config import get_settings

pytestmark = pytest.mark.skipif(
    not is_yara_available(),
    reason="yara-python not installed",
)


@pytest.fixture
def client(tmp_path: Path, monkeypatch):
    rules_dir = tmp_path / "rules"
    (rules_dir / "user").mkdir(parents=True)
    extract_dir = tmp_path / "extracted"
    extract_dir.mkdir()

    settings = get_settings()
    monkeypatch.setattr(settings, "yara_rules_dir", str(rules_dir))
    monkeypatch.setattr(settings, "kit_extract_dir", str(extract_dir))

    app = FastAPI()
    app.include_router(yara_router, prefix="/api/v1/yara")
    return TestClient(app)


GOOD_RULE = """
rule sample_user_rule {
    strings:
        $a = "playground"
    condition:
        $a
}
"""

BAD_RULE = """
rule oops {
    strings:
        $a = "missing-quote
    condition:
        $a
}
"""


def test_save_creates_file(client: TestClient, tmp_path: Path):
    r = client.put("/api/v1/yara/rules/user/myrule", json={"content": GOOD_RULE})
    assert r.status_code == 200
    body = r.json()
    assert body["compile_ok"] is True
    assert body["name"] == "myrule"
    assert body["relative_path"] == "user/myrule.yar"
    assert body["size"] > 0
    assert (tmp_path / "rules" / "user" / "myrule.yar").is_file()


def test_save_refuses_uncompilable_rule(client: TestClient, tmp_path: Path):
    r = client.put("/api/v1/yara/rules/user/broken", json={"content": BAD_RULE})
    assert r.status_code == 200  # we still 200 with compile_ok=False
    body = r.json()
    assert body["compile_ok"] is False
    assert body["compile_errors"]
    # File should NOT have been written.
    assert not (tmp_path / "rules" / "user" / "broken.yar").exists()


def test_save_rejects_invalid_name(client: TestClient):
    for bad in ["../escape", "/abs", "with space", "weird.dots", "-leadinghyphen", ""]:
        r = client.put(f"/api/v1/yara/rules/user/{bad}", json={"content": GOOD_RULE})
        assert r.status_code in (400, 404, 405), f"Expected reject for {bad!r}, got {r.status_code}"


def test_save_overwrites(client: TestClient, tmp_path: Path):
    client.put("/api/v1/yara/rules/user/dup", json={"content": GOOD_RULE})
    second = GOOD_RULE.replace("playground", "updated_marker")
    r = client.put("/api/v1/yara/rules/user/dup", json={"content": second})
    assert r.status_code == 200
    on_disk = (tmp_path / "rules" / "user" / "dup.yar").read_text()
    assert "updated_marker" in on_disk


def test_delete_removes_file(client: TestClient, tmp_path: Path):
    client.put("/api/v1/yara/rules/user/togo", json={"content": GOOD_RULE})
    assert (tmp_path / "rules" / "user" / "togo.yar").is_file()

    r = client.delete("/api/v1/yara/rules/user/togo")
    assert r.status_code == 204
    assert not (tmp_path / "rules" / "user" / "togo.yar").exists()


def test_delete_404_when_missing(client: TestClient):
    r = client.delete("/api/v1/yara/rules/user/nope")
    assert r.status_code == 404


def test_delete_rejects_invalid_name(client: TestClient):
    # Starlette normalises ``..`` in the URL before routing, so this
    # may resolve to a different route entirely (405).  Either way, the
    # request must not delete anything in our user dir.
    r = client.delete("/api/v1/yara/rules/user/../etc-passwd")
    assert r.status_code in (400, 404, 405)
    # Try names that get through the URL parser but should fail validation.
    for bad in ["with space", "weird.dots", "-leading"]:
        r = client.delete(f"/api/v1/yara/rules/user/{bad}")
        assert r.status_code == 400, f"Expected 400 for {bad!r}, got {r.status_code}"


def test_list_includes_user_rules(client: TestClient):
    client.put("/api/v1/yara/rules/user/listme", json={"content": GOOD_RULE})
    r = client.get("/api/v1/yara/rules")
    assert r.status_code == 200
    items = r.json()
    user = [x for x in items if x["source"] == "user"]
    assert any(x["name"] == "listme" for x in user)


def test_get_rule_returns_user_source(client: TestClient):
    client.put("/api/v1/yara/rules/user/readme_back", json={"content": GOOD_RULE})
    r = client.get("/api/v1/yara/rules/user/readme_back.yar")
    assert r.status_code == 200
    body = r.json()
    assert body["source"] == "user"
    assert "playground" in body["content"]


def test_status_counts_user_rules(client: TestClient):
    r0 = client.get("/api/v1/yara/status").json()
    client.put("/api/v1/yara/rules/user/counted", json={"content": GOOD_RULE})
    r1 = client.get("/api/v1/yara/status").json()
    assert r1["user_rule_files"] == r0["user_rule_files"] + 1


def test_playground_accepts_base64_upload(client: TestClient):
    payload_bytes = b"some binary blob with the word playground inside"
    b64 = base64.b64encode(payload_bytes).decode()
    r = client.post(
        "/api/v1/yara/playground",
        json={
            "rule_source": GOOD_RULE,
            "raw": [{"name": "upload.bin", "content_b64": b64}],
            "options": {"include_strings": True, "string_context_bytes": 16},
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["compile"]["ok"] is True
    assert body["stats"]["files_scanned"] == 1
    assert any(m["target_path"] == "upload.bin" for m in body["matches"])


def test_playground_rejects_invalid_base64(client: TestClient):
    r = client.post(
        "/api/v1/yara/playground",
        json={
            "rule_source": GOOD_RULE,
            "raw": [{"name": "bad.bin", "content_b64": "not-valid-base64!!!"}],
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert any(e["target"] == "bad.bin" and "base64" in e["error"] for e in body["target_errors"])


def test_playground_text_path_still_works(client: TestClient):
    r = client.post(
        "/api/v1/yara/playground",
        json={
            "rule_source": GOOD_RULE,
            "raw": [{"name": "snippet.txt", "content": "hello playground"}],
        },
    )
    assert r.status_code == 200
    body = r.json()
    assert body["stats"]["files_scanned"] == 1
    assert body["matches"]


def test_save_writes_under_user_dir_only(client: TestClient, tmp_path: Path):
    """Defense in depth — even if name validation regex were loosened,
    the resolve+relative_to check should keep writes contained.
    """
    # The router decorator pattern routes this to a 404 (no matching path).
    r = client.put("/api/v1/yara/rules/user/..%2Fescaped", json={"content": GOOD_RULE})
    # 400 (validation) / 404 (no route) / 405 (method-not-allowed after
    # path collapse) are all acceptable — what matters is no file was
    # written outside rules/user/.
    assert r.status_code in (400, 404, 405)
    rogue = tmp_path / "rules" / "escaped.yar"
    assert not rogue.exists()


# ── Multi-source kit scanning (browser-rendered HTML + extracted + raw) ──
#
# The user reported "0 files scanned" for kit e2442aec-… even though that
# kit has page.html + _browser_resources/ in /app/downloads.  Cause was
# Phase 1 only walking /app/extracted.  These tests cover the fix end-to-
# end at the API layer, with a mocked DB session so we don't need
# postgres in the test environment.


@pytest.fixture
def kit_aware_client(tmp_path: Path, monkeypatch):
    """TestClient with a mocked DB session that returns a fixed local_path
    for one known kit, plus extract/download dirs scaffolded under tmp.
    """
    rules_dir = tmp_path / "rules"
    (rules_dir / "user").mkdir(parents=True)
    extract_dir = tmp_path / "extracted"
    download_dir = tmp_path / "downloads"
    extract_dir.mkdir()
    download_dir.mkdir()

    settings = get_settings()
    monkeypatch.setattr(settings, "yara_rules_dir", str(rules_dir))
    monkeypatch.setattr(settings, "kit_extract_dir", str(extract_dir))
    monkeypatch.setattr(settings, "kit_download_dir", str(download_dir))

    # Build a fake kit with the same shape as the user's e2442aec-…:
    # only page.html + _browser_resources, no extracted dir.
    kit_id = "11111111-2222-3333-4444-555555555555"
    kit_dir = download_dir / kit_id
    kit_dir.mkdir()
    page = kit_dir / "page.html"
    page.write_text("<html>hello playground</html>")
    br = kit_dir / "_browser_resources"
    br.mkdir()
    (br / "001_loader.js").write_text("var x = 'playground';")

    # Mock DB session that supports both query shapes the router uses:
    #   select(Kit.id, Kit.local_path)   → r.id, r.local_path  (playground)
    #   select(Kit.local_path)           → r[0]                (scannable-files)
    class _FakeRow:
        def __init__(self, kid: str, path: str):
            self.id = kid
            self.local_path = path
        def __iter__(self):
            yield self.local_path
        def __getitem__(self, i):
            return [self.local_path][i]

    class _FakeResult:
        def __init__(self, rows):
            self._rows = rows
        def all(self):
            return self._rows
        def first(self):
            return self._rows[0] if self._rows else None

    class _FakeSession:
        async def execute(self, stmt):  # noqa: ARG002 — we ignore the stmt
            return _FakeResult([_FakeRow(kit_id, str(page))])

    async def _override_get_db():
        yield _FakeSession()

    from darla.database import get_db
    app = FastAPI()
    app.include_router(yara_router, prefix="/api/v1/yara")
    app.dependency_overrides[get_db] = _override_get_db

    client = TestClient(app)
    client.kit_id = kit_id  # type: ignore[attr-defined]
    return client


def test_scannable_files_includes_raw_and_browser_resources(kit_aware_client: TestClient):
    """The user's bug: a browser-rendered kit must surface page.html (raw)
    AND _browser_resources/*.js (browser_resource) — not 0 files.
    """
    kid = kit_aware_client.kit_id  # type: ignore[attr-defined]
    r = kit_aware_client.get(f"/api/v1/yara/scannable-files/{kid}")
    assert r.status_code == 200, r.text
    body = r.json()

    sources = {f["source"] for f in body["files"]}
    assert "raw" in sources, "page.html should appear with source=raw"
    assert "browser_resource" in sources, "_browser_resources/*.js should appear"
    assert body["scannable_count"] >= 2
    # counts_by_source should add up
    assert sum(body["counts_by_source"].values()) == body["scannable_count"]


def test_playground_scans_browser_rendered_kit(kit_aware_client: TestClient):
    """End-to-end: rule scanning a kit with no extracted dir should now
    produce matches against page.html and the browser resources.
    """
    kid = kit_aware_client.kit_id  # type: ignore[attr-defined]
    r = kit_aware_client.post(
        "/api/v1/yara/playground",
        json={
            "rule_source": GOOD_RULE,
            "kits": [{"kit_id": kid}],
            "options": {"include_strings": True, "string_context_bytes": 16},
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["compile"]["ok"] is True
    assert body["stats"]["files_scanned"] >= 2
    matched_paths = {m["target_path"] for m in body["matches"]}
    assert "page.html" in matched_paths
    assert any("_browser_resources/" in p for p in matched_paths)


def test_scannable_files_rejects_non_uuid(kit_aware_client: TestClient):
    r = kit_aware_client.get("/api/v1/yara/scannable-files/not-a-uuid")
    assert r.status_code == 400
