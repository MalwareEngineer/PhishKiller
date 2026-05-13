"""Integration test for the PhishMatch attribution endpoint.

This test hits a running ``darla-api`` container on ``localhost:8000``.
It creates an Actor + a Kit through the regular APIs, exercises the
attribute / re-attribute (promote) / unattribute flow, then cleans up.

Skipped automatically if the API isn't reachable — keeps the pure-unit
run fast.  Rationale for not mocking: the endpoint's whole value is
writing the right JSONB + confidence + timestamps to the junction row,
which is an integration surface by nature.
"""

from __future__ import annotations

import uuid

import httpx
import pytest

API_BASE = "http://localhost:8000/api/v1"
TIMEOUT = httpx.Timeout(10.0)


def _api_reachable_without_auth() -> bool:
    """True only when the API is reachable AND not requiring auth.

    These tests hit the API anonymously (no Bearer token).  Phase 4
    of RFC 0001 turned on auth gating — when ``PK_AUTH_ENABLED=true``,
    every protected endpoint returns 401 and the integration flow
    can't run.  Skip the suite in that case rather than producing a
    pile of misleading 401 errors.

    A future PR will add token support to integration tests; for now
    the skip is the correct trade-off.
    """
    try:
        # ``/kits`` requires auth when enabled — 401 here means API up
        # but locked.  200 means API up + open (disabled mode).
        r = httpx.get(f"{API_BASE}/kits", timeout=2.0)
        return r.status_code == 200
    except httpx.HTTPError:
        return False


pytestmark = pytest.mark.skipif(
    not _api_reachable_without_auth(),
    reason=(
        "darla-api not reachable at localhost:8000, OR auth is enabled "
        "(integration tests don't yet supply a token — set "
        "PK_AUTH_ENABLED=false to run them)"
    ),
)


# ---------------------------------------------------------------------------
# Helpers: create & tear down test fixtures through the public API.
# ---------------------------------------------------------------------------


def _create_actor(client: httpx.Client, name: str) -> str:
    r = client.post(
        "/actors",
        json={
            "name": name,
            "description": "phishmatch-test fixture; safe to delete",
            "aliases": [],
        },
    )
    r.raise_for_status()
    return r.json()["id"]


def _delete_actor(client: httpx.Client, actor_id: str) -> None:
    client.delete(f"/actors/{actor_id}")


def _pick_existing_analyzed_kit(client: httpx.Client) -> str | None:
    r = client.get("/kits", params={"status": "ANALYZED", "limit": 1})
    r.raise_for_status()
    items = r.json().get("items") or []
    return items[0]["id"] if items else None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.fixture
def api_client():
    with httpx.Client(base_url=API_BASE, timeout=TIMEOUT) as client:
        yield client


@pytest.fixture
def analyzed_kit_id(api_client: httpx.Client) -> str:
    kit_id = _pick_existing_analyzed_kit(api_client)
    if not kit_id:
        pytest.skip("no ANALYZED kits in DB to attach attribution to")
    return kit_id


@pytest.fixture(scope="module")
def test_actor_id():
    """One actor for the whole module — avoids per-test create/delete churn
    that races against the async session pool (POST /actors commits on the
    dependency teardown, and a brand-new POST to /phishmatch/.../attribute
    sometimes hits a session that doesn't yet see the new row)."""
    name = f"phishmatch-test-actor-{uuid.uuid4().hex[:8]}"
    with httpx.Client(base_url=API_BASE, timeout=TIMEOUT) as client:
        actor_id = _create_actor(client, name)
        # Poll until readable — be kind to async-session visibility lag.
        for _ in range(10):
            if client.get(f"/actors/{actor_id}").status_code == 200:
                break
            import time
            time.sleep(0.1)
        else:
            pytest.fail(f"actor {actor_id} never became readable after POST")
        yield actor_id
        _delete_actor(client, actor_id)


def test_attribute_creates_link_with_evidence_snapshot(
    api_client: httpx.Client, analyzed_kit_id: str, test_actor_id: str,
):
    evidence = {
        "total": 42.0,
        "tlsh": 0.0,
        "ioc": 30.0,
        "yara": 9.0,
        "source_url": 0.0,
        "redirect_chain": 3.0,
        "evidence": {
            "tlsh": [],
            "ioc": [
                {"type": "telegram_bot_token", "value": "123:AAA", "weight": 30.0}
            ],
            "yara": ["PhishKit_Microsoft_Branded_Page"],
            "source_url": [],
            "redirect": [],
        },
    }
    r = api_client.post(
        f"/phishmatch/kit/{analyzed_kit_id}/attribute",
        json={
            "entity_type": "actor",
            "entity_id": test_actor_id,
            "confidence": "suspected",
            "attributed_by": "pytest",
            "evidence_snapshot": evidence,
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["created"] is True
    assert body["confidence"] == "suspected"
    assert body["entity_id"] == test_actor_id
    assert body["kit_id"] == analyzed_kit_id
    assert body["attributed_at"]  # timestamp populated

    # Re-post with promoted confidence — must be idempotent (created=False).
    r2 = api_client.post(
        f"/phishmatch/kit/{analyzed_kit_id}/attribute",
        json={
            "entity_type": "actor",
            "entity_id": test_actor_id,
            "confidence": "verified",
            "attributed_by": "pytest",
            "evidence_snapshot": evidence,
        },
    )
    assert r2.status_code == 200, r2.text
    assert r2.json()["created"] is False
    assert r2.json()["confidence"] == "verified"

    # The kit's actors list should now include this actor (round-trip
    # confirmation that the junction row actually committed).
    kit = api_client.get(f"/kits/{analyzed_kit_id}").json()
    actor_ids = {a["id"] for a in kit.get("actors", [])}
    assert test_actor_id in actor_ids

    # Cleanup: unattribute.  Endpoint returns 204; second call 404.
    rdel = api_client.delete(
        f"/phishmatch/kit/{analyzed_kit_id}/attribute",
        params={"entity_type": "actor", "entity_id": test_actor_id},
    )
    assert rdel.status_code == 204

    rdel2 = api_client.delete(
        f"/phishmatch/kit/{analyzed_kit_id}/attribute",
        params={"entity_type": "actor", "entity_id": test_actor_id},
    )
    assert rdel2.status_code == 404


def test_attribute_rejects_unknown_confidence(
    api_client: httpx.Client, analyzed_kit_id: str, test_actor_id: str,
):
    r = api_client.post(
        f"/phishmatch/kit/{analyzed_kit_id}/attribute",
        json={
            "entity_type": "actor",
            "entity_id": test_actor_id,
            "confidence": "definitely-maybe",
        },
    )
    assert r.status_code == 400
    assert "confidence" in r.text.lower()


def test_attribute_rejects_missing_kit(
    api_client: httpx.Client, test_actor_id: str,
):
    missing_id = uuid.uuid4()
    r = api_client.post(
        f"/phishmatch/kit/{missing_id}/attribute",
        json={
            "entity_type": "actor",
            "entity_id": test_actor_id,
            "confidence": "suspected",
        },
    )
    assert r.status_code == 404
    assert "kit" in r.text.lower()


def test_attribute_rejects_missing_entity(
    api_client: httpx.Client, analyzed_kit_id: str,
):
    missing_actor = uuid.uuid4()
    r = api_client.post(
        f"/phishmatch/kit/{analyzed_kit_id}/attribute",
        json={
            "entity_type": "actor",
            "entity_id": str(missing_actor),
            "confidence": "suspected",
        },
    )
    assert r.status_code == 404


def test_phishmatch_for_kit_returns_expected_shape(
    api_client: httpx.Client, analyzed_kit_id: str,
):
    r = api_client.get(f"/phishmatch/kit/{analyzed_kit_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["kit_id"] == analyzed_kit_id
    for key in ("actors", "families", "campaigns"):
        assert key in body and isinstance(body[key], list)
    assert "min_surface_score" in body
    assert body["min_surface_score"] > 0
